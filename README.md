# Multi-router Topology Packet Handling

## Vedant H. Goradia

# Project Overview

## Description

This project involves enhancing the functionality of a router implementation, focusing on handling ARP requests and replies, ICMP messages and responses, and ensuring proper communication between clients and servers. Additionally, structs were introduced to aid in the implementation.

## Some Explanations

### sr_arpcache.c
- **sr_arpcache_sweepreqs():**
  - Iterated through cache requests and delegated the rest of the work to a helper function called `handle_arpreq()`.
  - Implemented a limit of 5 ARP requests per second, sending an ICMP host unreachable code if the limit is reached.
  - Debugged issues related to saving the next pointer in the linked list before traversal.

### sr_router.c
- **sr_handlepacket():**
  - Conducted tests to ensure that if there is an error, the packet is dropped.
  - Handled ARP requests and replies, ICMP messages, and responses.
  - Implemented functionality for forwarding packets based on destination IP.
  - Decremented TTL and sent ARP requests, waiting for and handling ARP responses.
  - Used ICMP error codes to indicate errors or send host unreachable messages.

## Testing and Debugging
- Employed print functions for testing purposes.
- Resolved challenges related to linked list traversal and implementation details.

## Additional Features
- Implemented traceroute functionality to visualize the path of transmitted packets.
- Utilized the ARP cache and the `lookup()` function to enhance functionality.
- Extended packet transmission protocol to handle a multi-router topology.

## Code Structure
- Maintained a modular structure with a defined structure outside of `sr_arpcache.c` and `sr_router.c`.
- Ensured proper memory management for headers, emphasizing their role in communication.

## Conclusion
The project builds upon a previous implementation, extending the router's capabilities to handle more complex network topologies. The modifications focused on ARP handling, ICMP functionality, and overall packet transmission. Thorough testing, debugging, and additional features contribute to a robust and functional router implementation.
