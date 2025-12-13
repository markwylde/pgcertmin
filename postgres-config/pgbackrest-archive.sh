#!/bin/sh
# Dummy pgbackrest archive script for pgBackRest compatibility
# This satisfies pgBackRest's archive_command check without actually archiving WAL
# WAL files are not archived - no PITR capability
exit 0
