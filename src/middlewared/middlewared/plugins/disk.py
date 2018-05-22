import asyncio
from collections import defaultdict
from datetime import datetime, timedelta
import errno
import glob
import os
import re
import signal
import subprocess
import sys
import sysctl
import tempfile

from bsd import geom, getswapinfo

from middlewared.common.camcontrol import camcontrol_list
from middlewared.common.smart.smartctl import get_smartctl_args
from middlewared.schema import accepts, Bool, Dict, List, Patch, Str
from middlewared.service import filterable, job, private, CallError, CRUDService
from middlewared.utils import Popen, run
from middlewared.utils.asyncio_ import asyncio_map

# FIXME: temporary import of SmartAlert until alert is implemented
# in middlewared
if '/usr/local/www' not in sys.path:
    sys.path.insert(0, '/usr/local/www')
from freenasUI.services.utils import SmartAlert

DISK_EXPIRECACHE_DAYS = 7
MIRROR_MAX = 5
RE_CAMCONTROL_DRIVE_LOCKED = re.compile(r'^drive locked\s+yes$', re.M)
RE_DA = re.compile('^da[0-9]+$')
RE_DD = re.compile(r'^(\d+) bytes transferred .*\((\d+) bytes')
RE_DSKNAME = re.compile(r'^([a-z]+)([0-9]+)$')
RE_ISDISK = re.compile(r'^(da|ada|vtbd|mfid|nvd|pmem)[0-9]+$')
RE_MPATH_NAME = re.compile(r'[a-z]+(\d+)')
RE_SED_RDLOCK_EN = re.compile(r'(RLKEna = Y|ReadLockEnabled:\s*1)', re.M)
RE_SED_WRLOCK_EN = re.compile(r'(WLKEna = Y|WriteLockEnabled:\s*1)', re.M)


class DiskService(CRUDService):

    class Config:
        datastore = 'storage.disk'
        datastore_prefix = 'disk_'
        datastore_extend = 'disk.disk_extend'

    @filterable
    async def query(self, filters=None, options=None):
        if filters is None:
            filters = []
        if options is None:
            options = {}
        options['prefix'] = 'disk_'
        filters.append(('expiretime', '=', None))
        options['extend'] = 'disk.disk_extend'
        return await self.middleware.call('datastore.query', 'storage.disk', filters, options)

    @private
    async def disk_extend(self, disk):
        disk.pop('enabled', None)
        disk['passwd'] = await self.middleware.call(
            'notifier.pwenc_decrypt',
            disk['passwd']
        )
        return disk

    @accepts(
        Str('id'),
        Dict(
            'disk_update',
            Bool('togglesmart'),
            Str('acousticlevel', enum=[
                'Disabled', 'Minimum', 'Medium', 'Maximum'
            ]),
            Str('advpowermgmt', enum=[
                'Disabled', '1', '64', '127', '128', '192', '254'
            ]),
            Str('description'),
            Str('hddstandby', enum=[
                'Always On', '5', '10', '20', '30', '60', '120', '180', '240', '300', '330'
            ]),
            Str('passwd'),
            Str('smartoptions'),
            register=True
        )
    )
    async def do_update(self, id, data):

        old = await self.middleware.call(
            'datastore.query',
            self._config.datastore,
            [('identifier', '=', id)],
            {'prefix': self._config.datastore_prefix, 'get': True}
        )
        old.pop('enabled', None)
        new = old.copy()
        new.update(data)

        if old['passwd'] != new['passwd']:
            new['passwd'] = await self.middleware.call(
                'notifier.pwenc_encrypt',
                new['passwd']
            )

        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            id,
            new,
            {'prefix': self._config.datastore_prefix}
        )

        if any(new[key] != old[key] for key in ['hddstandby', 'advpowermgmt', 'acousticlevel']):
            await self.middleware.call('notifier.start_ataidle', new['name'])

        if any(new[key] != old[key] for key in ['togglesmart', 'smartoptions']):

            if new['togglesmart']:
                await self.toggle_smart_on(new['name'])
            else:
                await self.toggle_smart_off(new['name'])

            await self._service_change('smartd', 'restart')

        updated_data = await self.query(
            [('identifier', '=', id)],
            {'get': True}
        )
        updated_data['id'] = id

        return updated_data

    @accepts(
        List('ids', items=[Str('id')]),
        Patch(
            'disk_update', 'disk_bulk_update',
            ('rm', {'name': 'description'}),
            ('rm', {'name': 'passwd'})
        )
    )
    async def bulk_update(self, ids, data):
        # TODO: Is this desired ?
        for id in ids:
            await self.update(id, data)

    @private
    def get_name(self, disk):
        if disk["multipath_name"]:
            return f"multipath/{disk['multipath_name']}"
        else:
            return disk["name"]

    @accepts(Bool("join_partitions"))
    async def get_unused(self, join_partitions=False):
        """
        Helper method to get all disks that are not in use, either by the boot
        pool or the user pools.
        """
        disks = await self.query([('name', 'nin', await self.get_reserved())])

        if join_partitions:
            for disk in disks:
                disk["partitions"] = await self.__get_partitions(disk)

        return disks

    @accepts(Dict(
        'options',
        Bool('unused', default=False),
    ))
    def get_encrypted(self, options):
        """
        Get all geli providers

        It might be an entire disk or a partition of type freebsd-zfs
        """
        providers = []

        disks_blacklist = []
        if options['unused']:
            disks_blacklist += self.middleware.call_sync('disk.get_reserved')

        geom.scan()
        klass_part = geom.class_by_name('PART')
        klass_label = geom.class_by_name('LABEL')
        if not klass_part:
            return providers

        for g in klass_part.geoms:
            for p in g.providers:

                if p.config['type'] != 'freebsd-zfs':
                    continue

                disk = p.geom.consumer.provider.name
                if disk in disks_blacklist:
                    continue

                try:
                    subprocess.run(
                        ['geli', 'dump', p.name],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
                    )
                except subprocess.CalledProcessError:
                    continue

                dev = None
                if klass_label:
                    for g in klass_label.geoms:
                        if g.name == p.name:
                            dev = g.provider.name
                            break

                if dev is None:
                    dev = p.name

                providers.append({
                    'name': p.name,
                    'dev': dev,
                    'disk': disk
                })

        return providers

    @accepts(
        List('devices', items=[Str('device')]),
        Str('passphrase', private=True),
    )
    @job(pipes=['input'])
    def decrypt(self, job, devices, passphrase=None):
        """
        Decrypt `devices` using uploaded encryption key
        """
        with tempfile.NamedTemporaryFile(dir='/tmp/') as f:
            f.write(job.pipes.input.r.read())
            f.flush()

            if passphrase:
                passf = tempfile.NamedTemporaryFile(mode='w+', dir='/tmp/')
                os.chmod(passf.name, 0o600)
                passf.write(passphrase)
                passf.flush()
                passphrase = passf.name

            failed = []
            for dev in devices:
                try:
                    self.middleware.call_sync(
                        'notifier.geli_attach_single',
                        dev,
                        f.name,
                        passphrase,
                    )
                except Exception:
                    failed.append(dev)

            if passphrase:
                passf.close()

            if failed:
                raise CallError(f'The following devices failed to attach: {", ".join(failed)}')
        return True

    @private
    async def get_reserved(self):
        reserved = [i async for i in await self.middleware.call('boot.get_disks')]
        reserved += [i async for i in await self.middleware.call('pool.get_disks')]
        reserved += [i async for i in self.__get_iscsi_targets()]
        return reserved

    async def __get_iscsi_targets(self):
        iscsi_target_extent_paths = [
            extent["iscsi_target_extent_path"]
            for extent in await self.middleware.call('datastore.query', 'services.iscsitargetextent',
                                                     [('iscsi_target_extent_type', '=', 'Disk')])
        ]
        for disk in await self.middleware.call('datastore.query', 'storage.disk',
                                               [('disk_identifier', 'in', iscsi_target_extent_paths)]):
            yield disk["disk_name"]

    async def __get_partitions(self, disk):
        partitions = []
        name = await self.middleware.call("disk.get_name", disk)
        for path in glob.glob(f"/dev/%s[a-fps]*" % name) or [f"/dev/{name}"]:
            info = (await run("/usr/sbin/diskinfo", path)).stdout.decode("utf-8").split("\t")
            if len(info) > 3:
                partitions.append({
                    "path": path,
                    "capacity": int(info[2]),
                })

        return partitions

    async def __get_smartctl_args(self, devname):
        camcontrol = await camcontrol_list()
        if devname not in camcontrol:
            return

        args = await get_smartctl_args(devname, camcontrol[devname])
        if args is None:
            return

        return args

    @private
    async def toggle_smart_off(self, devname):
        args = await self.__get_smartctl_args(devname)
        if args:
            await run('/usr/local/sbin/smartctl', '--smart=off', *args, check=False)

    @private
    async def toggle_smart_on(self, devname):
        args = await self.__get_smartctl_args(devname)
        if args:
            await run('/usr/local/sbin/smartctl', '--smart=on', *args, check=False)

    @private
    async def serial_from_device(self, name):
        args = await self.__get_smartctl_args(name)
        if args:
            p1 = await Popen(['smartctl', '-i'] + args, stdout=subprocess.PIPE)
            output = (await p1.communicate())[0].decode()
            search = re.search(r'Serial Number:\s+(?P<serial>.+)', output, re.I)
            if search:
                return search.group('serial')

        await self.middleware.run_in_thread(geom.scan)
        g = geom.geom_by_name('DISK', name)
        if g and g.provider.config.get('ident'):
            return g.provider.config['ident']

        return None

    @private
    @accepts(Str('name'))
    async def device_to_identifier(self, name):
        """
        Given a device `name` (e.g. da0) returns an unique identifier string
        for this device.
        This identifier is in the form of {type}string, "type" can be one of
        the following:
          - serial_lunid - for disk serial concatenated with the lunid
          - serial - disk serial
          - uuid - uuid of a ZFS GPT partition
          - label - label name from geom label
          - devicename - name of the device if any other could not be used/found

        Returns:
            str - identifier
        """
        await self.middleware.run_in_thread(geom.scan)

        g = geom.geom_by_name('DISK', name)
        if g and g.provider.config.get('ident'):
            serial = g.provider.config['ident']
            lunid = g.provider.config.get('lunid')
            if lunid:
                return f'{{serial_lunid}}{serial}_{lunid}'
            return f'{{serial}}{serial}'

        serial = await self.serial_from_device(name)
        if serial:
            return f'{{serial}}{serial}'

        klass = geom.class_by_name('PART')
        if klass:
            for g in klass.geoms:
                for p in g.providers:
                    if p.name == name:
                        # freebsd-zfs partition
                        if p.config['rawtype'] == '516e7cba-6ecf-11d6-8ff8-00022d09712b':
                            return f'{{uuid}}{p.config["rawuuid"]}'

        g = geom.geom_by_name('LABEL', name)
        if g:
            return f'{{label}}{g.provider.name}'

        g = geom.geom_by_name('DEV', name)
        if g:
            return f'{{devicename}}{name}'

        return ''

    @private
    def label_to_dev(self, label, geom_scan=True):
        if label.endswith('.nop'):
            label = label[:-4]
        elif label.endswith('.eli'):
            label = label[:-4]

        if geom_scan:
            geom.scan()
        klass = geom.class_by_name('LABEL')
        prov = klass.xml.find(f'.//provider[name="{label}"]/../name')
        if prov is not None:
            return prov.text

    @private
    @accepts(Str('name'))
    async def sync(self, name):
        """
        Syncs a disk `name` with the database cache.
        """
        # Skip sync disks on backup node
        if (
            not await self.middleware.call('system.is_freenas') and
            await self.middleware.call('notifier.failover_licensed') and
            await self.middleware.call('notifier.failover_status') == 'BACKUP'
        ):
            return

        # Do not sync geom classes like multipath/hast/etc
        if name.find("/") != -1:
            return

        disks = list((await self.middleware.call('device.get_info', 'DISK')).keys())

        # Abort if the disk is not recognized as an available disk
        if name not in disks:
            return
        ident = await self.device_to_identifier(name)
        qs = await self.middleware.call('datastore.query', 'storage.disk', [('disk_identifier', '=', ident)], {'order_by': ['disk_expiretime']})
        if ident and qs:
            disk = qs[0]
            new = False
        else:
            new = True
            qs = await self.middleware.call('datastore.query', 'storage.disk', [('disk_name', '=', name)])
            for i in qs:
                i['disk_expiretime'] = datetime.utcnow() + timedelta(days=DISK_EXPIRECACHE_DAYS)
                await self.middleware.call('datastore.update', 'storage.disk', i['disk_identifier'], i)
            disk = {'disk_identifier': ident}
        disk.update({'disk_name': name, 'disk_expiretime': None})

        await self.middleware.run_in_thread(geom.scan)
        g = geom.geom_by_name('DISK', name)
        if g:
            if g.provider.config['ident']:
                disk['disk_serial'] = g.provider.config['ident']
            if g.provider.mediasize:
                disk['disk_size'] = g.provider.mediasize
        if not disk.get('disk_serial'):
            disk['disk_serial'] = await self.serial_from_device(name) or ''
        reg = RE_DSKNAME.search(name)
        if reg:
            disk['disk_subsystem'] = reg.group(1)
            disk['disk_number'] = int(reg.group(2))
        if not new:
            await self.middleware.call('datastore.update', 'storage.disk', disk['disk_identifier'], disk)
        else:
            disk['disk_identifier'] = await self.middleware.call('datastore.insert', 'storage.disk', disk)

        # FIXME: use a truenas middleware plugin
        await self.middleware.call('notifier.sync_disk_extra', disk['disk_identifier'], False)

    @private
    @accepts()
    async def sync_all(self):
        """
        Synchronyze all disks with the cache in database.
        """
        # Skip sync disks on backup node
        if (
            not await self.middleware.call('system.is_freenas') and
            await self.middleware.call('notifier.failover_licensed') and
            await self.middleware.call('notifier.failover_status') == 'BACKUP'
        ):
            return

        sys_disks = list((await self.middleware.call('device.get_info', 'DISK')).keys())

        seen_disks = {}
        serials = []
        await self.middleware.run_in_thread(geom.scan)
        for disk in (await self.middleware.call('datastore.query', 'storage.disk', [], {'order_by': ['disk_expiretime']})):

            name = await self.middleware.call('notifier.identifier_to_device', disk['disk_identifier'])
            if not name or name in seen_disks:
                # If we cant translate the indentifier to a device, give up
                # If name has already been seen once then we are probably
                # dealing with with multipath here
                if not disk['disk_expiretime']:
                    disk['disk_expiretime'] = datetime.utcnow() + timedelta(days=DISK_EXPIRECACHE_DAYS)
                    await self.middleware.call('datastore.update', 'storage.disk', disk['disk_identifier'], disk)
                elif disk['disk_expiretime'] < datetime.utcnow():
                    # Disk expire time has surpassed, go ahead and remove it
                    await self.middleware.call('datastore.delete', 'storage.disk', disk['disk_identifier'])
                continue
            else:
                disk['disk_expiretime'] = None
                disk['disk_name'] = name

            reg = RE_DSKNAME.search(name)
            if reg:
                disk['disk_subsystem'] = reg.group(1)
                disk['disk_number'] = int(reg.group(2))
            serial = ''
            g = geom.geom_by_name('DISK', name)
            if g:
                if g.provider.config['ident']:
                    serial = disk['disk_serial'] = g.provider.config['ident']
                serial += g.provider.config.get('lunid') or ''
                if g.provider.mediasize:
                    disk['disk_size'] = g.provider.mediasize
            if not disk.get('disk_serial'):
                serial = disk['disk_serial'] = await self.serial_from_device(name) or ''

            if serial:
                serials.append(serial)

            # If for some reason disk is not identified as a system disk
            # mark it to expire.
            if name not in sys_disks and not disk['disk_expiretime']:
                    disk['disk_expiretime'] = datetime.utcnow() + timedelta(days=DISK_EXPIRECACHE_DAYS)
            await self.middleware.call('datastore.update', 'storage.disk', disk['disk_identifier'], disk)

            # FIXME: use a truenas middleware plugin
            await self.middleware.call('notifier.sync_disk_extra', disk['disk_identifier'], False)
            seen_disks[name] = disk

        for name in sys_disks:
            if name not in seen_disks:
                disk_identifier = await self.device_to_identifier(name)
                qs = await self.middleware.call('datastore.query', 'storage.disk', [('disk_identifier', '=', disk_identifier)])
                if qs:
                    new = False
                    disk = qs[0]
                else:
                    new = True
                    disk = {'disk_identifier': disk_identifier}
                disk['disk_name'] = name
                serial = ''
                g = geom.geom_by_name('DISK', name)
                if g:
                    if g.provider.config['ident']:
                        serial = disk['disk_serial'] = g.provider.config['ident']
                    serial += g.provider.config.get('lunid') or ''
                    if g.provider.mediasize:
                        disk['disk_size'] = g.provider.mediasize
                if not disk.get('disk_serial'):
                    serial = disk['disk_serial'] = await self.serial_from_device(name) or ''
                if serial:
                    if serial in serials:
                        # Probably dealing with multipath here, do not add another
                        continue
                    else:
                        serials.append(serial)
                reg = RE_DSKNAME.search(name)
                if reg:
                    disk['disk_subsystem'] = reg.group(1)
                    disk['disk_number'] = int(reg.group(2))

                if not new:
                    await self.middleware.call('datastore.update', 'storage.disk', disk['disk_identifier'], disk)
                else:
                    disk['disk_identifier'] = await self.middleware.call('datastore.insert', 'storage.disk', disk)
                # FIXME: use a truenas middleware plugin
                await self.middleware.call('notifier.sync_disk_extra', disk['disk_identifier'], True)

    @private
    async def sed_unlock_all(self):
        advconfig = await self.middleware.call('system.advanced.config')
        disks = await self.middleware.call('disk.query')

        # If no SED password was found we can stop here
        if not advconfig.get('sed_passwd') and not any([d['passwd'] for d in disks]):
            return

        result = await asyncio_map(lambda disk: self.sed_unlock(disk['name'], disk, advconfig), disks, 16)
        locked = list(filter(lambda x: x['locked'] is True, result))
        if locked:
            disk_names = ', '.join([i['name'] for i in locked])
            self.logger.warn(f'Failed to unlock following SED disks: {disk_names}')
            raise CallError('Failed to unlock SED disks', errno.EACCES)
        return True

    @private
    async def sed_unlock(self, disk_name, disk=None, _advconfig=None):
        if _advconfig is None:
            _advconfig = await self.middleware.call('system.advanced.config')

        devname = f'/dev/{disk_name}'
        # We need two states to tell apart when disk was successfully unlocked
        locked = None
        unlocked = None
        password = _advconfig.get('sed_passwd')

        if disk is None:
            disk = await self.middleware.call('disk.query', [('name', '=', disk_name)])
            if disk and disk[0]['passwd']:
                password = disk[0]['passwd']
        elif disk.get('passwd'):
            password = disk['passwd']

        rv = {'name': disk_name, 'locked': None}

        if not password:
            # If there is no password no point in continuing
            return rv

        # Try unlocking TCG OPAL using sedutil
        cp = await run('sedutil-cli', '--query', devname, check=False)
        if cp.returncode == 0:
            output = cp.stdout.decode(errors='ignore')
            if 'Locked = Y' in output:
                locked = True
                cp = await run('sedutil-cli', '--setLockingRange', '0', 'RW', password, devname, check=False)
                if cp.returncode == 0:
                    locked = False
                    unlocked = True
            elif 'Locked = N' in output:
                locked = False

        # Try ATA Security if SED was not unlocked and its not locked by OPAL
        if not unlocked and not locked:
            cp = await run('camcontrol', 'security', devname, check=False)
            if cp.returncode == 0:
                output = cp.stdout.decode()
                if RE_CAMCONTROL_DRIVE_LOCKED.search(output):
                    locked = True
                    cp = await run(
                        'camcontrol', 'security', devname,
                        '-U', _advconfig['sed_user'],
                        '-k', password,
                        check=False,
                    )
                    if cp.returncode == 0:
                        locked = False
                        unlocked = True
                else:
                    locked = False

        if unlocked:
            try:
                # Disk needs to be retasted after unlock
                with open(devname, 'wb'):
                    pass
            except OSError:
                pass
        elif locked:
            self.logger.error(f'Failed to unlock {disk_name}')
        rv['locked'] = locked
        return rv

    @private
    async def sed_initial_setup(self, disk_name, password):
        """
        NO_SED - Does not support SED
        ACCESS_GRANTED - Already setup and `password` is a valid password
        LOCKING_DISABLED - Locking range is disabled
        SETUP_FAILED - Initial setup call failed
        SUCCESS - Setup successfully completed
        """
        devname = f'/dev/{disk_name}'

        cp = await run('sedutil-cli', '--isValidSED', devname, check=False)
        if b' SED ' not in cp.stdout:
            return 'NO_SED'

        cp = await run('sedutil-cli', '--listLockingRange', '0', password, devname, check=False)
        if cp.returncode == 0:
            output = cp.stdout.decode()
            if RE_SED_RDLOCK_EN.search(output) and RE_SED_WRLOCK_EN.search(output):
                return 'ACCESS_GRANTED'
            else:
                return 'LOCKING_DISABLED'

        try:
            await run('sedutil-cli', '--initialSetup', password, devname)
        except subprocess.CalledProcessError as e:
            self.logger.debug(f'initialSetup failed for {disk_name}:\n{e.stdout}{e.stderr}')
            return 'SETUP_FAILED'

        # OPAL 2.0 disks do not enable locking range on setup like Enterprise does
        try:
            await run('sedutil-cli', '--enableLockingRange', '0', password, devname)
        except subprocess.CalledProcessError as e:
            self.logger.debug(f'enableLockingRange failed for {disk_name}:\n{e.stdout}{e.stderr}')
            return 'SETUP_FAILED'

        return 'SUCCESS'

    async def __multipath_create(self, name, consumers, mode=None):
        """
        Create an Active/Passive GEOM_MULTIPATH provider
        with name ``name`` using ``consumers`` as the consumers for it

        Modes:
            A - Active/Active
            R - Active/Read
            None - Active/Passive

        Returns:
            True in case the label succeeded and False otherwise
        """
        cmd = ["/sbin/gmultipath", "label", name] + consumers
        if mode:
            cmd.insert(2, f'-{mode}')
        p1 = await Popen(cmd, stdout=subprocess.PIPE)
        if (await p1.wait()) != 0:
            return False
        return True

    async def __multipath_next(self):
        """
        Find out the next available name for a multipath named diskX
        where X is a crescenting value starting from 1

        Returns:
            The string of the multipath name to be created
        """
        await self.middleware.run_in_thread(geom.scan)
        numbers = sorted([
            int(RE_MPATH_NAME.search(g.name).group(1))
            for g in geom.class_by_name('MULTIPATH').geoms if RE_MPATH_NAME.match(g.name)
        ])
        if not numbers:
            numbers = [0]
        for number in range(1, numbers[-1] + 2):
            if number not in numbers:
                break
        else:
            raise ValueError('Could not find multipaths')
        return f'disk{number}'

    @private
    @accepts()
    async def multipath_sync(self):
        """
        Synchronize multipath disks

        Every distinct GEOM_DISK that shares an ident (aka disk serial)
        with conjunction of the lunid is considered a multipath and will be
        handled by GEOM_MULTIPATH.

        If the disk is not currently in use by some Volume or iSCSI Disk Extent
        then a gmultipath is automatically created and will be available for use.
        """

        await self.middleware.run_in_thread(geom.scan)

        mp_disks = []
        for g in geom.class_by_name('MULTIPATH').geoms:
            for c in g.consumers:
                p_geom = c.provider.geom
                # For now just DISK is allowed
                if p_geom.clazz.name != 'DISK':
                    self.logger.warn(
                        "A consumer that is not a disk (%s) is part of a "
                        "MULTIPATH, currently unsupported by middleware",
                        p_geom.clazz.name
                    )
                    continue
                mp_disks.append(p_geom.name)

        reserved = await self.get_reserved()

        is_freenas = await self.middleware.call('system.is_freenas')

        serials = defaultdict(list)
        active_active = []
        for g in geom.class_by_name('DISK').geoms:
            if not RE_DA.match(g.name) or g.name in reserved or g.name in mp_disks:
                continue
            if not is_freenas:
                descr = g.provider.config.get('descr') or ''
                if (
                    descr == 'STEC ZeusRAM' or
                    descr.startswith('VIOLIN') or
                    descr.startswith('3PAR')
                ):
                    active_active.append(g.name)
            serial = ''
            v = g.provider.config.get('ident')
            if v:
                serial = v
            v = g.provider.config.get('lunid')
            if v:
                serial += v
            if not serial:
                continue
            size = g.provider.mediasize
            serials[(serial, size)].append(g.name)
            serials[(serial, size)].sort(key=lambda x: int(x[2:]))

        disks_pairs = [disks for disks in list(serials.values())]
        disks_pairs.sort(key=lambda x: int(x[0][2:]))

        # Mode is Active/Passive for FreeNAS
        mode = None if is_freenas else 'R'
        for disks in disks_pairs:
            if not len(disks) > 1:
                continue
            name = await self.__multipath_next()
            await self.__multipath_create(name, disks, 'A' if disks[0] in active_active else mode)

        # Scan again to take new multipaths into account
        await self.middleware.run_in_thread(geom.scan)
        mp_ids = []
        for g in geom.class_by_name('MULTIPATH').geoms:
            _disks = []
            for c in g.consumers:
                p_geom = c.provider.geom
                # For now just DISK is allowed
                if p_geom.clazz.name != 'DISK':
                    continue
                _disks.append(p_geom.name)

            qs = await self.middleware.call('datastore.query', 'storage.disk', [
                ['OR', [
                    ['disk_name', 'in', _disks],
                    ['disk_multipath_member', 'in', _disks],
                ]],
            ])
            if qs:
                diskobj = qs[0]
                mp_ids.append(diskobj['disk_identifier'])
                update = False  # Make sure to not update if nothing changed
                if diskobj['disk_multipath_name'] != g.name:
                    update = True
                    diskobj['disk_multipath_name'] = g.name
                if diskobj['disk_name'] in _disks:
                    _disks.remove(diskobj['disk_name'])
                if _disks and diskobj['disk_multipath_member'] != _disks[-1]:
                    update = True
                    diskobj['disk_multipath_member'] = _disks.pop()
                if update:
                    await self.middleware.call('datastore.update', 'storage.disk', diskobj['disk_identifier'], diskobj)

        # Update all disks which were not identified as MULTIPATH, resetting attributes
        for disk in (await self.middleware.call('datastore.query', 'storage.disk', [('disk_identifier', 'nin', mp_ids)])):
            if disk['disk_multipath_name'] or disk['disk_multipath_member']:
                disk['disk_multipath_name'] = ''
                disk['disk_multipath_member'] = ''
                await self.middleware.call('datastore.update', 'storage.disk', disk['disk_identifier'], disk)

    @private
    async def swaps_configure(self):
        """
        Configures swap partitions in the system.
        We try to mirror all available swap partitions to avoid a system
        crash in case one of them dies.
        """
        await self.middleware.run_in_thread(geom.scan)

        used_partitions = set()
        swap_devices = []
        klass = geom.class_by_name('MIRROR')
        if klass:
            for g in klass.geoms:
                # Skip gmirror that is not swap*
                if not g.name.startswith('swap') or g.name.endswith('.sync'):
                    continue
                consumers = list(g.consumers)
                # If the mirror is degraded lets remove it and make a new pair
                if len(consumers) == 1:
                    c = consumers[0]
                    await self.swaps_remove_disks([c.provider.geom.name])
                else:
                    swap_devices.append(f'mirror/{g.name}')
                    for c in consumers:
                        # Add all partitions used in swap, removing .eli
                        used_partitions.add(c.provider.name.strip('.eli'))

        klass = geom.class_by_name('PART')
        if not klass:
            return

        # Get all partitions of swap type, indexed by size
        swap_partitions_by_size = defaultdict(list)
        for g in klass.geoms:
            for p in g.providers:
                # if swap partition
                if p.config['rawtype'] == '516e7cb5-6ecf-11d6-8ff8-00022d09712b':
                    if p.name not in used_partitions:
                        # Try to save a core dump from that.
                        # Only try savecore if the partition is not already in use
                        # to avoid errors in the console (#27516)
                        await run('savecore', '-z', '-m', '5', '/data/crash/', f'/dev/{p.name}', check=False)
                        swap_partitions_by_size[p.mediasize].append(p.name)

        dumpdev = False
        unused_partitions = []
        for size, partitions in swap_partitions_by_size.items():
            # If we have only one partition add it to unused_partitions list
            if len(partitions) == 1:
                unused_partitions += partitions
                continue

            for i in range(int(len(partitions) / 2)):
                if len(swap_devices) > MIRROR_MAX:
                    break
                part_a, part_b = partitions[0:2]
                partitions = partitions[2:]
                if not dumpdev:
                    dumpdev = await dempdev_configure(part_a)
                try:
                    name = new_swap_name()
                    if name is None:
                        # Which means maximum has been reached and we can stop
                        break
                    await run('gmirror', 'create', '-b', 'prefer', name, part_a, part_b)
                except Exception:
                    self.logger.warn(f'Failed to create gmirror {name}', exc_info=True)
                    continue
                swap_devices.append(f'mirror/{name}')
                # Add remaining partitions to unused list
                unused_partitions += partitions

        # If we could not make even a single swap mirror, add the first unused
        # partition as a swap device
        if not swap_devices and unused_partitions:
            if not dumpdev:
                dumpdev = await dempdev_configure(unused_partitions[0])
            swap_devices.append(unused_partitions[0])

        for name in swap_devices:
            if not os.path.exists(f'/dev/{name}.eli'):
                await run('geli', 'onetime', name)
            await run('swapon', f'/dev/{name}.eli', check=False)

        return swap_devices

    @private
    async def swaps_remove_disks(self, disks):
        """
        Remove a given disk (e.g. ["da0", "da1"]) from swap.
        it will offline if from swap, remove it from the gmirror (if exists)
        and detach the geli.
        """
        await self.middleware.run_in_thread(geom.scan)
        providers = {}
        for disk in disks:
            partgeom = geom.geom_by_name('PART', disk)
            if not partgeom:
                continue
            for p in partgeom.providers:
                if p.config['rawtype'] == '516e7cb5-6ecf-11d6-8ff8-00022d09712b':
                    providers[p.id] = p
                    break

        if not providers:
            return

        klass = geom.class_by_name('MIRROR')
        if not klass:
            return

        mirrors = set()
        for g in klass.geoms:
            for c in g.consumers:
                if c.provider.id in providers:
                    mirrors.add(g.name)
                    del providers[c.provider.id]

        swapinfo_devs = [s.devname for s in getswapinfo()]

        for name in mirrors:
            devname = f'mirror/{name}.eli'
            devpath = f'/dev/{devname}'
            if devname in swapinfo_devs:
                await run('swapoff', devpath)
            if os.path.exists(devpath):
                await run('geli', 'detach', devname)
            await run('gmirror', 'destroy', name)

        for p in providers.values():
            devname = f'{p.name}.eli'
            if devname in swapinfo_devs:
                await run('swapoff', f'/dev/{devname}')
            if os.path.exists(f'/dev/{devname}'):
                await run('geli', 'detach', devname)

    @private
    async def wipe_quick(self, dev, size=None):
        """
        Perform a quick wipe of a disk `dev` by the first few and last few megabytes
        """
        # If the size is too small, lets just skip it for now.
        # In the future we can adjust dd size
        if size and size < 33554432:
            return
        await run('dd', 'if=/dev/zero', f'of=/dev/{dev}', 'bs=1m', 'count=32')
        try:
            cp = await run('diskinfo', dev)
            size = int(int(re.sub(r'\s+', ' ', cp.stdout.decode()).split()[2]) / (1024))
        except subprocess.CalledProcessError:
            self.logger.error(f'Unable to determine size of {dev}')
        else:
            # This will fail when EOL is reached
            await run('dd', 'if=/dev/zero', f'of=/dev/{dev}', 'bs=1m', f'oseek={int(size / 1024) - 32}', check=False)

    @accepts(Str('dev'), Str('mode', enum=['QUICK', 'FULL', 'FULL_RANDOM']))
    @job(lock=lambda args: args[0])
    async def wipe(self, job, dev, mode):
        """
        Performs a wipe of a disk `dev`.
        It can be of the following modes:
          - QUICK: clean the first few and last megabytes of every partition and disk
          - FULL: write whole disk with zero's
          - FULL_RANDOM: write whole disk with random bytes
        """
        await self.swaps_remove_disks([dev])

        # First do a quick wipe of every partition to clean things like zfs labels
        if mode == 'QUICK':
            await self.middleware.run_in_thread(geom.scan)
            klass = geom.class_by_name('PART')
            for g in klass.xml.findall(f'./geom[name=\'{dev}\']'):
                for p in g.findall('./provider'):
                    size = p.find('./mediasize')
                    if size is not None:
                        try:
                            size = int(size.text)
                        except ValueError:
                            size = None
                    name = p.find('./name')
                    await self.wipe_quick(name.text, size=size)

        await run('gpart', 'destroy', '-F', f'/dev/{dev}', check=False)

        # Wipe out the partition table by doing an additional iterate of create/destroy
        await run('gpart', 'create', '-s', 'gpt', f'/dev/{dev}')
        await run('gpart', 'destroy', '-F', f'/dev/{dev}')

        if mode == 'QUICK':
            await self.wipe_quick(dev)
        else:
            cp = await run('diskinfo', dev)
            size = int(re.sub(r'\s+', ' ', cp.stdout.decode()).split()[2])

            proc = await Popen([
                'dd',
                'if=/dev/{}'.format('zero' if mode == 'FULL' else 'random'),
                f'of=/dev/{dev}',
                'bs=1m',
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            async def dd_wait():
                while True:
                    if proc.returncode is not None:
                        break
                    os.kill(proc.pid, signal.SIGINFO)
                    await asyncio.sleep(1)

            asyncio.ensure_future(dd_wait())

            while True:
                line = await proc.stderr.readline()
                if line == b'':
                    break
                line = line.decode()
                reg = RE_DD.search(line)
                if reg:
                    job.set_progress((int(reg.group(1)) / size) * 100, extra={'speed': int(reg.group(2))})

        await self.sync(dev)


def new_swap_name():
    """
    Get a new name for a swap mirror

    Returns:
        str: name of the swap mirror
    """
    for i in range(MIRROR_MAX):
        name = f'swap{i}'
        if not os.path.exists(f'/dev/mirror/{name}'):
            return name


async def dempdev_configure(name):
    # Configure dumpdev on first swap device
    if not os.path.exists('/dev/dumpdev'):
        try:
            os.unlink('/dev/dumpdev')
        except OSError:
            pass
        os.symlink(f'/dev/{name}', '/dev/dumpdev')
        await run('dumpon', f'/dev/{name}')
    return True


async def _event_devfs(middleware, event_type, args):
    data = args['data']
    if data.get('subsystem') != 'CDEV':
        return

    if data['type'] == 'CREATE':
        disks = await middleware.run_in_thread(lambda: sysctl.filter('kern.disks')[0].value.split())
        # Device notified about is not a disk
        if data['cdev'] not in disks:
            return
        # TODO: hack so every disk is not synced independently during boot
        # This is a performance issue
        if os.path.exists('/tmp/.sync_disk_done'):
            await middleware.call('disk.sync', data['cdev'])
            await middleware.call('disk.sed_unlock', data['cdev'])
            await middleware.call('disk.multipath_sync')
            try:
                with SmartAlert() as sa:
                    sa.device_delete(data['cdev'])
            except Exception:
                pass
    elif data['type'] == 'DESTROY':
        # Device notified about is not a disk
        if not RE_ISDISK.match(data['cdev']):
            return
        # TODO: hack so every disk is not synced independently during boot
        # This is a performance issue
        if os.path.exists('/tmp/.sync_disk_done'):
            await middleware.call('disk.sync_all')
            await middleware.call('disk.multipath_sync')
            try:
                with SmartAlert() as sa:
                    sa.device_delete(data['cdev'])
            except Exception:
                pass
            # If a disk dies we need to reconfigure swaps so we are not left
            # with a single disk mirror swap, which may be a point of failure.
            await middleware.call('disk.swaps_configure')


def setup(middleware):
    # Listen to DEVFS events so we can sync on disk attach/detach
    middleware.event_subscribe('devd.devfs', _event_devfs)
