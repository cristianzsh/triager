#!/usr/bin/env python3
#
# PyWMIPersistenceFinder.py (Python 3 port)
# Original author: David Pany - Mandiant (FireEye) - 2017
# Adjustments to Python3 by Cristian Souza (cristianmsbr@gmail.com)

import sys
import re
import string

PRINTABLE_CHARS = set(string.printable)


def main():
    """Main function for everything!"""

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <OBJECTS.DATA file>")
        sys.exit(1)

    objects_path = sys.argv[1]

    print("\n    Enumerating FilterToConsumerBindings...")

    # Precompiled match objects to search each line with
    event_consumer_mo = re.compile(r'([\w\_]*EventConsumer\.Name\=\")([\w\s]*)(\")')
    event_filter_mo = re.compile(r'(_EventFilter\.Name\=\")([\w\s]*)(\")')

    # Dictionaries that will store bindings, consumers, and filters
    bindings_dict = {}
    consumer_dict = {}
    filter_dict = {}

    # Read objects.data 4 lines at a time to look for bindings
    # latin-1 ensures 1:1 byte->unicode mapping (won't choke on arbitrary bytes)
    with open(objects_path, "r", encoding="latin-1", errors="ignore") as objects_file:
        lines_list = [objects_file.readline() for _ in range(4)]
        current_line = lines_list[-1]

        while current_line:
            potential_page = " ".join(lines_list)

            # Look for FilterToConsumerBindings
            if "_FilterToConsumerBinding" in potential_page:
                consumer_match = event_consumer_mo.search(potential_page)
                filter_match = event_filter_mo.search(potential_page)

                if consumer_match and filter_match:
                    event_consumer_name = consumer_match.group(2)
                    event_filter_name = filter_match.group(2)

                    # Add to dicts if they don't already exist (use set() to avoid dupes)
                    consumer_dict.setdefault(event_consumer_name, set())
                    filter_dict.setdefault(event_filter_name, set())

                    binding_id = f"{event_consumer_name}-{event_filter_name}"
                    bindings_dict.setdefault(binding_id, {
                        "event_consumer_name": event_consumer_name,
                        "event_filter_name": event_filter_name,
                    })

            # Increment lines and look again
            current_line = objects_file.readline()
            lines_list.append(current_line)
            lines_list.pop(0)

    print(
        "    {} FilterToConsumerBinding(s) Found. Enumerating Filters and Consumers..."
        .format(len(bindings_dict))
    )

    # Read objects.data 4 lines at a time to look for filters and consumers
    with open(objects_path, "r", encoding="latin-1", errors="ignore") as objects_file:
        lines_list = [objects_file.readline() for _ in range(4)]
        current_line = lines_list[-1]

        while current_line:
            potential_page = " ".join(lines_list).replace("\n", "")

            # Check each potential page for the consumers we are looking for
            if "EventConsumer" in potential_page:
                for event_consumer_name in list(consumer_dict.keys()):
                    # Can't precompile regex because it is dynamically created with each consumer name
                    if "CommandLineEventConsumer" in potential_page:
                        consumer_mo = re.compile(
                            r"(CommandLineEventConsumer)(\x00\x00)(.*?)(\x00)(.*?)"
                            r"({})(\x00\x00)?([^\x00]*)?"
                            .format(re.escape(event_consumer_name))
                        )
                        consumer_match = consumer_mo.search(potential_page)
                        if consumer_match:
                            noisy_string = consumer_match.group(3)

                            # Python 3: filter() returns iterator; build a string explicitly
                            cleaned_args = "".join(ch for ch in noisy_string if ch in PRINTABLE_CHARS)

                            consumer_details = (
                                "\n\t\tConsumer Type: {}\n\t\tArguments:     {}"
                                .format(consumer_match.group(1), cleaned_args)
                            )
                            if consumer_match.group(6):
                                consumer_details += "\n\t\tConsumer Name: {}".format(consumer_match.group(6))
                            if consumer_match.group(8):
                                consumer_details += "\n\t\tOther:         {}".format(consumer_match.group(8))
                            consumer_dict[event_consumer_name].add(consumer_details)

                    else:
                        consumer_mo = re.compile(
                            r"(\w*EventConsumer)(.*?)({})(\x00\x00)([^\x00]*)(\x00\x00)([^\x00]*)"
                            .format(re.escape(event_consumer_name))
                        )
                        consumer_match = consumer_mo.search(potential_page)
                        if consumer_match:
                            consumer_details = "{} ~ {} ~ {} ~ {}".format(
                                consumer_match.group(1),
                                consumer_match.group(3),
                                consumer_match.group(5),
                                consumer_match.group(7),
                            )
                            consumer_dict[event_consumer_name].add(consumer_details)

            # Check each potential page for the filters we are looking for
            for event_filter_name in list(filter_dict.keys()):
                if event_filter_name in potential_page:
                    filter_mo = re.compile(
                        r"({})(\x00\x00)([^\x00]*)(\x00\x00)".format(re.escape(event_filter_name))
                    )
                    filter_match = filter_mo.search(potential_page)
                    if filter_match:
                        filter_details = "\n\t\tFilter name:  {}\n\t\tFilter Query: {}".format(
                            filter_match.group(1),
                            filter_match.group(3),
                        )
                        filter_dict[event_filter_name].add(filter_details)

            current_line = objects_file.readline()
            lines_list.append(current_line)
            lines_list.pop(0)

    # Print results to stdout. CSV will be in future version.
    print("\n    Bindings:\n")
    for binding_name, binding_details in bindings_dict.items():
        if (
            "BVTConsumer-BVTFilter" in binding_name or
            "SCM Event Log Consumer-SCM Event Log Filter" in binding_name
        ):
            print(
                "        {}\n                (Common binding based on consumer and filter names,"
                " possibly legitimate)".format(binding_name)
            )
        else:
            print("        {}".format(binding_name))

        event_filter_name = binding_details["event_filter_name"]
        event_consumer_name = binding_details["event_consumer_name"]

        # Print binding details if available
        if consumer_dict.get(event_consumer_name):
            for event_consumer_details in consumer_dict[event_consumer_name]:
                print("            Consumer: {}".format(event_consumer_details))
        else:
            print("            Consumer: {}".format(event_consumer_name))

        # Print details for each filter found for this filter name
        for event_filter_details in filter_dict.get(event_filter_name, []):
            print("\n            Filter: {}".format(event_filter_details))
            print()

if __name__ == "__main__":
    main()
