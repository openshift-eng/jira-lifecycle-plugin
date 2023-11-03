#!/usr/bin/python

import argparse
import json
import logging
import os.path

import yaml
from yaml.parser import ParserError

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger('prowConfigTool')


def generate_tide_query(options, tide_queries):
    query = {}
    for param in ['included_branches', 'excluded_branches', 'labels', 'missing_labels', 'repos']:
        if options[param] is None:
            continue
        query.update({get_query_key(param): sorted(options[param])})
    # If there are no repos defined, then pick it from the "first" query in the file
    if 'repos' not in query or query['repos'] is None:
        if len(tide_queries) >= 1:
            query.update({'repos': list(tide_queries[0]['repos'])})
    return query


def tide_create_handler(options, tide_queries):
    query = generate_tide_query(options, tide_queries)
    if 'repos' not in query or query['repos'] is None:
        logger.error('Unable to determine repo configuration for query!')
        exit(-1)
    if query in tide_queries:
        logger.error('Query already defined!')
        return False
    tide_queries.append(query)
    return True


def tide_delete_handler(options, tide_queries):
    generated = generate_tide_query(options, tide_queries)
    for query in tide_queries:
        if query == generated:
            logger.info(f' - Deleting query:\n{json.dumps(query, indent=4, default=str)}')
            tide_queries.remove(query)
            return True
    return False


def tide_clean_handler(options, tide_queries):
    return check_for_duplicates(tide_queries, options['delete_duplicates'])


def check_for_duplicates(queries, delete_duplicates):
    for index, query in enumerate(queries):
        if query in queries[:index]:
            if delete_duplicates:
                logger.info(f' - Deleting Duplicate query:\n{json.dumps(query, indent=4, default=str)}')
                queries.remove(query)
                return True
            else:
                logger.info(f' - Found Duplicate query:\n{json.dumps(query, indent=4, default=str)}')
    return False


def tide_query_parameter_handler(options, tide_queries):
    match options['action']:
        case 'add':
            return tide_query_add_handler(options, tide_queries)
        case 'remove':
            return tide_query_remove_handler(options, tide_queries)
    return False


def get_query_key(parameter_key):
    match parameter_key:
        case 'repos':
            return 'repos'
        case 'labels':
            return 'labels'
        case 'missing_labels':
            return 'missingLabels'
        case 'included_branches':
            return 'includedBranches'
        case 'excluded_branches':
            return 'excludedBranches'
        case _:
            logger.error(f'Unknown parameter key: {parameter_key}')
            exit(-1)


def add_tide_query_parameter(options, queries, included_in, excluded_from):
    if options[included_in] is None:
        return False

    query_include_key = get_query_key(included_in)
    query_exclude_key = get_query_key(excluded_from)

    modified = False
    for value in options[included_in]:
        for query in queries:
            if query_include_key in query:
                if value not in query[query_include_key]:
                    logger.info(f' - Adding "{value}" to {query_include_key}')
                    query[query_include_key].append(value)
                    query[query_include_key] = sorted(query[query_include_key])
                    modified = True
            else:
                logger.info(f' - Creating "{query_include_key}" stanza with value: [{value}]')
                query[query_include_key] = [value]
                modified = True
            if query_exclude_key in query:
                if value in query[query_exclude_key]:
                    logger.info(f' - Removing "{value}" from {query_exclude_key}')
                    query[query_exclude_key].remove(value)
                    modified = True
    return modified


def remove_tide_query_parameter(options, queries, included_in):
    if options[included_in] is None:
        return False

    query_include_key = get_query_key(included_in)

    modified = False
    for value in options[included_in]:
        for query in queries:
            if query_include_key in query:
                if value in query[query_include_key]:
                    logger.info(f' - Removing "{value}" from {query_include_key}')
                    query[query_include_key].remove(value)
                    modified = True
    return modified


def tide_query_add_handler(options, tide_queries):
    modified = False
    for params in [('included_branches', 'excluded_branches'), ('excluded_branches', 'included_branches'), ('labels', 'missing_labels'), ('missing_labels', 'labels')]:
        result = add_tide_query_parameter(options, tide_queries, *params)
        modified = modified or result
    return modified


def tide_query_remove_handler(options, tide_queries):
    modified = False
    for key in ['included_branches', 'excluded_branches', 'labels', 'missing_labels']:
        modified = modified or remove_tide_query_parameter(options, tide_queries, key)
    return modified


def tide_operation_handler(options, prow_config):
    if 'tide' in prow_config:
        tide_config = prow_config['tide']

        if 'queries' in tide_config:
            tide_queries = tide_config['queries']

            match options['operation']:
                case 'create':
                    return tide_create_handler(options, tide_queries)
                case 'delete':
                    return tide_delete_handler(options, tide_queries)
                case 'clean':
                    return tide_clean_handler(options, tide_queries)
                case 'parameter':
                    return tide_query_parameter_handler(options, tide_queries)
    return False


def process_prow_configuration(options):
    issues = []
    for root, _, filenames in os.walk(options['config']):
        for filename in filenames:
            full_path_filename = os.path.join(root, filename)
            if filename != "_prowconfig.yaml":
                logger.debug('Skipping: {}'.format(full_path_filename))
                continue

            with open(full_path_filename, 'r') as prow_config:
                try:
                    logger.debug('Reading: {}'.format(full_path_filename))
                    config = yaml.safe_load(prow_config)
                except ParserError as e:
                    logger.error(f'Error reading Prow configuration for {full_path_filename}: {e}')
                    issues.append((full_path_filename, e))
                    continue

            if config is None:
                logger.error(f'Empty config for: {full_path_filename}')
                continue

            logger.info('Processing: {}'.format(full_path_filename))
            modified = False
            match options['plugin']:
                case 'tide':
                    modified = tide_operation_handler(options, config)

            if modified:
                with open(full_path_filename, 'w') as prow_config:
                    logger.debug('Writing: {}'.format(full_path_filename))
                    yaml.dump(config, prow_config, sort_keys=True)

    return issues


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenShift Prow Configuration Tool')
    parser.add_argument('-c', '--config', help='The location of the Prow configuration(s) to process', required=True, default=None)

    subparsers = parser.add_subparsers(title='plugins', description='valid plugins', help='Supported Prow plugins', required=True)

    tide_parser = subparsers.add_parser('tide', help='Prow Tide plugin')
    tide_parser.set_defaults(plugin='tide')
    tide_parser.add_argument('-i', '--included-branches', help='Git Branch name(s) to include', action='append')
    tide_parser.add_argument('-e', '--excluded-branches', help='Git Branch name(s) to exclude', action='append')
    tide_parser.add_argument('-l', '--labels', help='Label(s) value', action='append')
    tide_parser.add_argument('-m', '--missing-labels', help='Missing label(s) value', action='append')
    tide_parser.add_argument('-r', '--repos', help='Git Repo name(s)', action='append')

    tide_subparsers = tide_parser.add_subparsers(title='tide operations', description='valid tide operations', help='Supported operations', required=True)
    tide_create_parser = tide_subparsers.add_parser('create', help='Create Tide query')
    tide_create_parser.set_defaults(operation='create')

    tide_delete_parser = tide_subparsers.add_parser('delete', help='Delete Tide query')
    tide_delete_parser.set_defaults(operation='delete')

    tide_clean_parser = tide_subparsers.add_parser('clean', help='Clean Tide queries')
    tide_clean_parser.set_defaults(operation='clean')
    tide_clean_parser.add_argument('--delete-duplicates', help='Delete duplicate entries', action='store_true')

    tide_parameter_parser = tide_subparsers.add_parser('parameter', help='Manage Tide query parameter(s)')
    tide_parameter_parser.set_defaults(operation='parameter')

    tide_parameter_subparsers = tide_parameter_parser.add_subparsers(title='query parameter subcommands', description='valid query parameter subcommands',
                                                                     help='Supported query parameter operations', required=True)
    tide_query_parameter_add_parser = tide_parameter_subparsers.add_parser('add', help='Bulk add the specified parameters(s) to Tide queries')
    tide_query_parameter_add_parser.set_defaults(action='add')
    tide_query_parameter_remove_parser = tide_parameter_subparsers.add_parser('remove', help='Bulk remove the specified parameters(s) from Tide queries')
    tide_query_parameter_remove_parser.set_defaults(action='remove')

    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument('-v', '--verbose', help='Enable verbose output', action='store_true')

    args = vars(parser.parse_args())

    if args['verbose']:
        logger.setLevel(logging.DEBUG)

    if not os.path.exists(args['config']):
        logger.error(f'Specified location "{args["config"]}" does not exist!')
        exit(-1)

    logger.debug(f'Options:\n{json.dumps(args, indent=4, default=str)}')

    errors = process_prow_configuration(args)
    if len(errors) > 0:
        logger.error('Errors occurred during execution!')
        exit(len(errors))
