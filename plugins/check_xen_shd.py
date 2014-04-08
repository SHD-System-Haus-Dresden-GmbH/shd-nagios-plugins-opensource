#!/usr/bin/env python
# coding: utf-8
"""

Note: Critical and warning threshold formatting follow the Nagios plugin guidelines
https://www.nagios-plugins.org/doc/guidelines.html#THRESHOLDFORMAT

Example:
 ./check_xen_shd.py vm-status -H 192.168.95.205 -U root -P netlog --UUID b9abba39-4d19-f7a5-2f22-75092d848ae4
 ./check_xen_shd.py host-memory -H 192.168.95.205 -U root -P netlog --check-all -c 9669528000 -w 950 --used

"""

import logging
import sys
import nagiosplugin
import argparse

import XenAPI
# Import both socket and xmlrpclib to deal with XenAPI exceptions
import socket

try:
    import xmlrpc.client as xmlrpclib # for python 3
except ImportError:
    import xmlrpclib # for python 2

from pprint import pprint

_VERSION = 'check_xen_shd.py Version 0.1.0'
_log = logging.getLogger("nagiosplugin")


_GET_ALL_RECORDS_FETCHED = 'get_all_records fetched {0} records'

class ServerError(Exception):
    pass


class LoginError(Exception):
    pass

#Formating functions
def fmt_units(metric, context):
    returns = '{0} has {1} free'.format(metric.name, size_of_fmt(metric.value))
    return returns

def fmt_status(metric, context):
    # returns = '{0} is {1} instead of {2}'.format(metric.name, metric.value.lower(), context.status.lower())
    returns = '{0} is {1}'.format(metric.name, metric.value.lower())
    return returns


def size_of_fmt(num):
    """
    Convert a size indication from byte into easily human readable number.
    @param num: Size in byte.
    @return: String, containing easily human readable size.
    """
    for unit in ['bytes', 'KB', 'MB', 'GB']:
        # if num < 1024.0 and num > -1024.0:
        if -1024.0 < num < 1024.0:
            return "%3.1f%s" % (num, unit)
        num /= 1024.0
    return "%3.1f%s" % (num, 'TB')


def convert_to_byte(size):
    size, unit = get_unit_of_size(size)
    units = ['kb', 'mb', 'gb', 'tb', 'pb', 'eb']
    try:
        exp = (units.index(unit.lower()) + 1) * 10
    except ValueError:
        raise ValueError('')
    converted = size << exp
    _log.debug('{0}{1} -> {2} byte.'.format(size, unit, converted))
    return converted


def get_unit_of_size(size):
    """
    Split unit and number of a given (byte) size.
    """
    import re
    unit = re.search(r'(\d*)(\D*)$',size)
    number, unit = unit.groups()
    return int(number), unit


class StatusResult(nagiosplugin.Result):
    def __new__(cls, state, hint, metric):
        if not metric:
            raise RuntimeError('StatusResult always needs metric')
        return tuple.__new__(cls, (state, hint, metric))

    def __str__(self):
        if self.hint:
            hint = (self.hint.violation if hasattr(self.hint, 'violation')
                    else self.hint)
            # return '{0} ({1})'.format(self.metric.description, hint)
            return '{0}'.format(self.metric.description, hint)
        return str(self.metric.description)


class StatusCompareContext(nagiosplugin.Context):

    def __init__(self, name, status='', fmt_metric=None,
                 result_cls=StatusResult):
        super(StatusCompareContext, self).__init__(name, fmt_metric=fmt_metric,
                                                   result_cls=result_cls)
        self.status = status

    def evaluate(self, metric, resource):
        if self.status.lower() == metric.value.lower():
            return self.result_cls(nagiosplugin.Ok,
                                   self.status,
                                   metric=metric)
        else:
            return self.result_cls(nagiosplugin.Critical,
                                   self.status,
                                   metric=metric)

class StatusSummary(nagiosplugin.Summary):
    def ok(self, results):
        if len(results.results) > 1:
            result = 'All {0} VM are {1}.'.format(len(results.results), results.results[0].metric)
        else:
            result = str(results[0])
        return result
        # return str(results[0])

    def problem(self, results):
        first_significant = str(results.first_significant)
        number_of_failed = len(results.most_significant)
        if number_of_failed > 1:
            return '{0} and {1} other VM have the same status.'.format(first_significant, number_of_failed - 1)
        elif number_of_failed == 1:
            return '{0}'.format(first_significant)
        else:
            return first_significant


class XenSession(object):
    def __init__(self, host, user, password):

        self.host = host
        self.user = user
        self.password = password

    def login(self):
        try:
            # print self.session.last_login_method  # session debug
            self.session = XenAPI.Session('https://' + self.host)
        except XenAPI.Failure:
            raise ServerError('Server "{0}" not reachable'.format(self.host))

        try:
            self.session.login_with_password(self.user,
                                             self.password)  # get session id

        except XenAPI.Failure:
            raise LoginError('Credentials for user "{0}"wrong'.format(self.user))
        except xmlrpclib.ResponseError:
            raise ServerError('Server sent wrong response. '
                              'Check if XenServer is running and reachable under that address.')

    def __del__(self):
        self.logout()

    def logout(self):
        try:
            self.session.logout()
        except (socket.error, xmlrpclib.ResponseError):
            pass


class XenQuery(object):
    """
    Helper for querying XenServer xapi.
    """

    def __init__(self, session):
        try:
            self.xen_session = session
        except XenAPI.Failure as ex:
            raise ex

    def create_condition_string(self, conditions):
        """
        Returns a condition string
        @param conditions: List with ('field name', field content') tuples
        @return: String which can be parsed by XenAPI's get_all_records_where() method.
        """
        if len(conditions) < 1:
            raise RuntimeError('Conditions list cannot be empty')
        if ((conditions.__class__ != list) or
                (conditions[0].__class__ != tuple) or
                    (conditions[0][0].__class__) != str or
                (conditions[0][1].__class__ != str)):
            raise RuntimeError("Conditions list has to be in the form of [('field_name', 'field_content'),]")
        condition_string = ''
        for entry in conditions:
            field_name = entry[0]
            condition_string += 'field "{0}" = "{1}" or '.format(field_name,
                                                               entry[1])
        return condition_string[:-4]


    def get_records_where(self, xenapi_object, field_attr_list):
        if xenapi_object.__class__ != str:
            raise RuntimeError('"{0}" has to be a string.'.format(xenapi_object))
        condition = self.create_condition_string(field_attr_list)
        records = getattr(self.xen_session.session.xenapi, xenapi_object).get_all_records_where(
            condition)
        _log.debug(_GET_ALL_RECORDS_FETCHED.format(len(records)))
        if records == {}:
            raise RuntimeError(
                'No records could be fetched. Check for errors in the name or uuid.')
        return records

    def get_all_records_from_individual_obj(self, xenapi_object, names=None, uuids=None):
        """
        Fetches the full record of the given XenAPI object's names and uuids
        @param xenapi_object: XenAPI object to query
        @param names: List of XenAPI object names
        @param uuids: List of XenAPI object uuids
        @return: XenAPI dict
        """
        tuple_list = []
        try:
            for name in names:
                # XenAPI uses name__label internally but name_label in all other cases
                tuple_list.append(('name__label', name))
        except TypeError:
            pass
        try:
            for uuid in uuids:
                tuple_list.append(('uuid', uuid))
        except TypeError:
            pass
        records = self.get_records_where(xenapi_object, tuple_list)
        return records

    def get_all_records(self,xenapi_object, exclude=None):
        # remove and move specific data acquisition back to resource?

        records = dict()
        if exclude  ==  None:
            exclude = []

        if xenapi_object == 'SR':
            all_records = getattr(self.xen_session.session.xenapi,
                              xenapi_object).get_all_records()

            # Filter for non-writable SR?
            # - get all the vdbs and loop through them

            # - you could just cheat and exclude any SR with a size of
            # less than 5gig. The physical dvd drive and the xentools drive will
            # never have an allocation greater than that
            _log.debug(_GET_ALL_RECORDS_FETCHED.format(len(all_records)))
            if all_records == {}:
                raise RuntimeError(
                    'No records could be fetched. Check for errors in the name or uuid.')
            #TODO: CHECK IF VIABLE!
            for ref in all_records:

                # Warn the user if there are indications that the SR
                # might be a physical DVD drive or a mounted ISO image.
                if ((all_records[ref]['physical_size'] == all_records[ref]['physical_utilisation'])
                    and all_records[ref]['name_label'] not in exclude
                    and all_records[ref]['uuid'] not in exclude):
                    # ef8707e1-ce4f-e9b1-7681-b487ae5a16a2
                    s = ("{0} might be a DVD drive or a mounted image. "
                    "Please exclude it via '--uuid-exclude {1}'")
                    _log.debug(s.format(all_records[ref]['name_label'],
                                          all_records[ref]['uuid']))

                records[ref] = all_records[ref]
            return records

        if xenapi_object == 'VM':
            condition = 'field "is_a_snapshot" = "false" '
            condition += 'and field "is_a_template" = "false" '
            condition += 'and field "is_control_domain" = "false" '
            condition += 'and field "is_snapshot_from_vmpp" = "false"'
            all_records = self.xen_session.session.xenapi.VM.get_all_records_where(condition)
            _log.debug(_GET_ALL_RECORDS_FETCHED.format(len(records)))
            if all_records == {}:
                raise RuntimeError('No records could be fetched.')
            for record in all_records:
                record_name = all_records[record]['name_label']
                record_uuid = all_records[record]['uuid']
                # if (not all_records[record]['name_label'] in exclude or
                #         not all_records[record]['uuid'] in exclude):
                if not record_name in exclude and not record_uuid in exclude:
                    records[record] = all_records[record]
            return records


        if xenapi_object in ['host_metrics', 'host']:
            all_records = getattr(self.xen_session.session.xenapi,
                                  xenapi_object).get_all_records()
            _log.debug(
                _GET_ALL_RECORDS_FETCHED.format(len(all_records)))
            if all_records == {}:
                raise RuntimeError(
                    'No records could be fetched. Check for errors in the name or uuid.')

            records = all_records

            return records

        raise NotImplementedError('"{0}" not  in get_all_records'.format(xenapi_object))



class XenServerResource(nagiosplugin.Resource):
    """Basic information needed for connecting to XenServer via XenAPI"""

    def __init__(self, host, user, password, check_all, uuid=None, xen_name=None,
                 used=False, xen_name_exclude=None, uuid_exclude=None):
        """
        @param host: XenServer that provides the needed information via XenAPI.
        @param user: Authorized user on the XenServer.
        @param password: Password of the authorized user.
        @param xen_name: Name of the resource to check.
        @param uuid: UUID of the resource to check
        @param used: If True, the check will use `used` values instead of `free` values
        """
        self.host = host
        self.user = user
        self.password = password
        self.uuid = uuid
        self.xen_name = xen_name
        self.used = used
        self.check_all = check_all

        if not uuid_exclude:
            self.uuid_exclude = []
        else:
            self.uuid_exclude = uuid_exclude

        if not xen_name_exclude:
            self.xen_name_exclude = []
        else:
            self.xen_name_exclude = xen_name_exclude

    def build_connection(self):
        _log.info('opening connection to XenServer; host:%s', self.host)
        self.session = XenSession(self.host, self.user, self.password)
        _log.info('login at the server; user:%s pw:%s', self.user,
                  self.password)
        self.session.login()
        query = XenQuery(self.session)
        return query

    def close_connection(self):
        self.session.logout()


class HostMemory(XenServerResource):
    def __init__(self, host, user, password, check_all, used=None, uuid=None, xen_name=None, uuid_exclude=None, xen_name_exclude=None):
        super(HostMemory, self).__init__(host=host,
                                             user=user,
                                             password=password,
                                             uuid=uuid,
                                             xen_name=xen_name,
                                             check_all=check_all,
                                             uuid_exclude=uuid_exclude,
                                             xen_name_exclude=xen_name_exclude,
                                             used=used,
        )

    def probe(self):
        connection = self.build_connection()
        _log.info('Fetching host metrics')
        # vm_name = connection.get_vm_name_label(self.uuid)
        exclude = self.uuid_exclude + self.xen_name_exclude
        if self.check_all:
            records = connection.get_all_records(xenapi_object='host', exclude=exclude)
        else:
            records = connection.get_all_records_from_individual_obj(xenapi_object='host',
                                             names=self.xen_name,
                                             uuids=self.uuid)

        host_dict = dict()
        for record in records:
            uuid = records[record]['uuid']
            name = records[record]['name_label']
            metrics_ref = records[record]['metrics']
            metrics_record = connection.xen_session.session.xenapi.host_metrics.get_record(
                metrics_ref)
            host_dict[uuid] = {'Name': name,
                               'Metrics': metrics_record,
                    }
        if self.used:
            for host in host_dict:
                name_label = host_dict[host]['Name']
                mem_free = int(host_dict[host]['Metrics']['memory_free'])
                mem_total = int(host_dict[host]['Metrics']['memory_total'])
                mem_used = mem_total - mem_free
                yield nagiosplugin.Metric(
                    name=name_label[:20],
                    value=mem_used,
                    uom='B',
                    min=0,
                    context='host_memory')
        else:
            for host in host_dict:
                name_label = host_dict[host]['Name']
                value = int(host_dict[host]['Metrics']['memory_free'])
                yield nagiosplugin.Metric(
                    name=name_label[:20],
                                          value=value,
                                          uom='B',
                                          min=0,
                                          context='host_memory')


class SRUtilisation(XenServerResource):
    """
    Check SR for physical size and utilisation
    """

    def __init__(self, host, user, password, used, check_all, xen_name=None,
                 uuid=None, xen_name_exclude=None, uuid_exclude=None):
        """
        @param mem_used: If True, check against used memory instead of remaining free
        """
        super(SRUtilisation, self).__init__(host=host,
                                            user=user,
                                            password=password,
                                            uuid=uuid,
                                            xen_name=xen_name,
                                            check_all=check_all,
                                            used=used,
                                            xen_name_exclude=xen_name_exclude,
                                            uuid_exclude=uuid_exclude,
                                            )

    def get_all_records(self, connection, exclude=None):
        records = dir()
        if exclude == None:
            exclude = []
        all_records = connection.xen_session.session.xenapi.SR.get_all_records()

        #TODO: CHECK IF VIABLE!
        # Filter for non-writable SR?
        # - get all the vdbs and loop through them

        # - you could just cheat and exclude any SR with a size of
        # less than 5gig. The physical dvd drive and the xentools drive will
        # never have an allocation greater than that

        for ref in all_records:

            # Warn the user if there are indications that the SR
            # might be a physical DVD drive or a mounted ISO image.
            if ((all_records[ref]['physical_size'] == all_records[ref][
                'physical_utilisation'])
                and all_records[ref]['name_label'] not in exclude
                and all_records[ref]['uuid'] not in exclude):
                # ef8707e1-ce4f-e9b1-7681-b487ae5a16a2
                s = ("{0} might be a DVD drive or a mounted image. "
                     "Please exclude it via '--uuid-exclude {1}'")
                _log.debug(s.format(all_records[ref]['name_label'],
                                      all_records[ref]['uuid']))

            records[ref] = all_records[ref]
        return records

    def probe(self):

        connection = self.build_connection()
        _log.info('Fetching Storage Repository info')
        exclude = self.xen_name_exclude + self.uuid_exclude
        if self.check_all:
            records = connection.get_all_records(xenapi_object='SR', exclude=exclude)
        else:
            records = connection.get_all_records_from_individual_obj(xenapi_object='SR',
                                             names=self.xen_name,
                                             uuids=self.uuid)
        # remove excludes

        _log.debug(
            _GET_ALL_RECORDS_FETCHED.format(len(records)))
        if records == {}:
            raise RuntimeError(
                'No records could be fetched. Check for errors in the name or uuid.')

        uuid_name_dict = dict()
        for ref in records:
            uuid = records[ref]['uuid']


            if uuid in self.uuid_exclude:
                continue
            name_label = records[ref]['name_label']
            if name_label in self.xen_name_exclude:
                continue
            sr_physical_utilisation = int(records[ref]['physical_utilisation'])
            sr_physical_size = int(records[ref]['physical_size'])
            _log.debug('raw data: {0} {1} {2} {3}'.format(name_label, uuid, sr_physical_utilisation, sr_physical_size))
            sr_physical_free = sr_physical_size - sr_physical_utilisation
            uuid_name_dict[uuid] = {'Name': name_label,
                                    'physical_utilisation': sr_physical_utilisation,
                                    'physical_size': sr_physical_size,
                                    'physical_free': sr_physical_free,
                                    }
        self.close_connection()
        for uuid in uuid_name_dict:
            # '{0}'.format(self.sr_uuid_dict[uuid]['Name'][:20],

            yield nagiosplugin.Metric(
                '{0}'.format(uuid_name_dict[uuid]['Name']),
                uuid_name_dict[uuid]['physical_free'],
                uom='B',
                min=0,
                context='sr_physical_free')



class VMStatus(XenServerResource):
    """Domain model: virtual machine status.
    Checks a VM for a specific status.
    The `probe` method returns the status of the given vm.
    """

    def __init__(self, host, user, password, check_all,  xen_name=None, uuid=None, xen_name_exclude=None, uuid_exclude=None):
        super(VMStatus, self).__init__(host=host,
                                       user=user,
                                       password=password,
                                       uuid=uuid,
                                       xen_name=xen_name,
                                       check_all=check_all,
                                       xen_name_exclude=xen_name_exclude,
                                       uuid_exclude=uuid_exclude,
                                       )

    def probe(self):
        connection = self.build_connection()
        _log.info('Fetching vm status')
        exclude = self.uuid_exclude + self.xen_name_exclude
        if self.check_all:
            records = dict()
            records = connection.get_all_records(xenapi_object='VM', exclude=exclude)
            # condition = 'field "is_a_snapshot" = "false" '
            # condition += 'and field "is_a_template" = "false" '
            # condition += 'and field "is_control_domain" = "false" '
            # condition += 'and field "is_snapshot_from_vmpp" = "false"'
            # all_records = connection.xen_session.session.xenapi.VM.get_all_records_where(condition)
            # _log.debug(_GET_ALL_RECORDS_FETCHED.format(len(all_records)))
            # if all_records == {}:
            #     raise RuntimeError(
            #         'No records could be fetched.')
            # for record in all_records:
            #     if (not all_records[record]['name_label'] in exclude or
            #             not all_records[record]['uuid'] in exclude):
            #         records[record] = all_records[record]

        else:
            records = connection.get_all_records_from_individual_obj(
                xenapi_object='VM',
                names=self.xen_name,
                uuids=self.uuid)

        self.close_connection()
        uuid_name_dict = dict()
        for record in records:
            uuid_name_dict[records[record]['uuid']] = {'Name': records[record]['name_label'],
                                             'vm_status': records[record]['power_state']}

        for uuid in uuid_name_dict:
            # yield nagiosplugin.Metric('vm_status', status, context='vm_status')
            yield nagiosplugin.Metric(
                '{0}'.format(uuid_name_dict[uuid]['Name']),
                uuid_name_dict[uuid]['vm_status'],
                context='vm_status'
            )


class ArgumentParserError(Exception):
    pass

class ThrowingArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentParserError(message)

@nagiosplugin.guarded
def main():
    # parser = argparse.ArgumentParser()
    parser = ThrowingArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose',
                        action='count', default=0,
                        help='Set verbosity level. (-v \ -vv \ -vvv)')
    parser.add_argument('-t', '--timeout', dest='timeout',
                        default=10)

    connection_parser = argparse.ArgumentParser(add_help=False)
    connection_parser.add_argument('-H', '--host', dest='host', required=True,
                        help='XenServer host/pool master.')
    connection_parser.add_argument('-U', '--user', dest='user', required=True,
                        help='Authorized user on the XenServer.')
    connection_parser.add_argument('-P', '--password', dest='password', required=True,
                        help='Password of the authorized user.')
    connection_parser.add_argument('--check-all', dest='check_all', action='store_true',
                        help='Check all VMs. (Templates, snaphots, dom0 and VMPP snapsots are excluded)')

    connection_parser.add_argument('--UUID', dest='uuid', nargs='*',
                        help='UUID of the object to check (required if no name is given).')
    connection_parser.add_argument('--NAME', dest='xen_name', nargs='*',
                        help='Name of the object to check (required if no uuid is given).')
    connection_parser.add_argument('--UUID-Exclude', dest='uuid_exclude', nargs='*',
                        help='UUID of the object to exclude from the check.')
    connection_parser.add_argument('--NAME-Exclude', dest='xen_name_exclude', nargs='*',
                        help='Name of the object to exclude from the check.')

    threshold_parser = argparse.ArgumentParser(add_help=False)
    threshold_parser.add_argument('-w', '--warning', dest='warning',
                        help='Raise warning if measurment is above the desired byte value.')
    threshold_parser.add_argument('-c', '--critical', dest='critical',
                        help='Raise critical if measurment is above the desired byte value.')

    subparsers = parser.add_subparsers(help='Subcommands Help Text to add here')

    #  Add sub-parser to create new sub-command
    parser_sr_utilisation = subparsers.add_parser('sr-utilisation',
                                                  parents=[connection_parser, threshold_parser],
                                                  help='Check the utilisation of Storage Repositories.')
    #  Add arguments for that sub-command
    parser_sr_utilisation.add_argument('--used', dest='used', action='store_true',
                                       help='The given thresholds represent the maximum the SR can be utilized, '
                                            'e.g. "Is critical if more than 500GB are used".')

    #  Set the context and resource classes
    parser_sr_utilisation.set_defaults(resource_class=SRUtilisation,
                                       context_class=nagiosplugin.ScalarContext,
                                       context_name='sr_physical_free',
    #  assign the respective arguments
                                       resource_args=['used'],
                                       context_args=['warning', 'critical'],
    #  add format string/callable to format the output.
                                       fmt_metric=fmt_units,
                                       summary_class=nagiosplugin.Summary()
    )

    parser_host_memory = subparsers.add_parser('host-memory',
                                                    parents=[connection_parser, threshold_parser],
                                                    help='Check the memory of one or more Xen hosts.')
    parser_host_memory.add_argument('--used', dest='used', action='store_true',
                                    help='The given thresholds represent the maximum the hosts can be utilized, '
                                         'e.g. "Is critical if more than 4GB are used".')

    parser_host_memory.set_defaults(
        context_class=nagiosplugin.ScalarContext,
        context_name='host_memory',
        context_args=['warning', 'critical'],
        resource_class=HostMemory,
        resource_args=['used'],
        fmt_metric=fmt_units,
        summary_class=nagiosplugin.Summary()
    )

    parser_vm_status = subparsers.add_parser('vm-status',
                                             parents=[connection_parser],
                                             help='Check the status of a given VM')
    parser_vm_status.add_argument('--status', type=str, dest='status',
                                  help='Desired status of the VM',
                                  default='running')
    parser_vm_status.set_defaults(
        context_class=StatusCompareContext,
        context_name='vm_status',
        context_args=['status'],
        fmt_metric=fmt_status,
        resource_class=VMStatus,
        resource_args=[],
        summary_class=StatusSummary()
    )
    # args = parser.parse_args()
    try:
        args = parser.parse_args()
    except ArgumentParserError as ex:
        print('{0}'.format(ex))
        sys.exit(3)

    if not (args.uuid or args.xen_name) and not args.check_all:
        parser.error('UUID and name missing. Add a least one.')
    arguments = vars(args)

    resource_kwargs = dict()
    for key in arguments:
        #  Assign default arguments which are needed to create a connection
        #  and find the object to query for
        if key in ['host', 'user', 'password', 'xen_name', 'uuid', 'check_all', 'xen_name_exclude', 'uuid_exclude']:
            resource_kwargs[key] = arguments[key]
    for name in args.resource_args:
        resource_kwargs[name] = getattr(args, name)

    context_kwargs = dict()
    for arg in args.context_args:
        context_kwargs[arg] = getattr(args, arg)

    context_kwargs['name'] = arguments['context_name']
    context_kwargs['fmt_metric'] = arguments['fmt_metric']

    resource = args.resource_class(**resource_kwargs)
    context = args.context_class(**context_kwargs)

    try:
        summary = arguments['summary_class']
    except KeyError:
        RuntimeError('Summary class configuration not possible.')

    check = nagiosplugin.Check(resource,
                               context,
                               summary,
                               )
    # execute check
    check.main(timeout=arguments['timeout'],
               verbose=arguments['verbose']
               )

if __name__ == '__main__':
    main()
