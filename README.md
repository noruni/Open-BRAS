Open-BRAS
=========

My project looks to improve upon the existing ISP BRAS model using SDN and the OpenFlow protocol. This research will be conducted as my dissertation for COMP520-14C Report of an Investigation at the University of Waikato, Hamilton, New Zealand.

Student: Craig Osborne

Supervisor: Dr. Richard Nelson

Project Abstract:

In carrier-grade Internet Service Provider (ISP) networks, the Broadband Remote Access Server (BRAS), also more contemporarily known as the Broadband Network Gateway (BNG), is a specialised server which sits at the core of an ISP's network. It is responsible for the facilitation and aggregation of user sessions from the ISP's access network, and provides layer 3 connectivity through the ISP's backbone network to the Internet in addition to other important related tasks. In a typical ISP, because of the BRAS's need to cater for the traffic of a large number of concurrent users accessing the internet, it is often one of the most expensive pieces of equipment in an ISP's network. An ISP's dependence on the BRAS in a typical network model can present multiple challenges, such as the considerable costs associated with replacing a BRAS in the event of a fault, or the singular point of failure for all customer access to the internet for the ISP. My project aims to redesign the existing ISP BRAS model using Software Defined Networking (SDN) and the OpenFlow protocol, to remove the singular dependence on this expensive, operations-critical appliance. This will most likely involve implementing software controllers running on commodity hardware to govern the BRAS decision making, which will issue commands to distributed series of layer 2 switches.
