# pcap-commentator
Read and Add Comment to a packet of Pcapng file

Installation
============


    pip3 install setuptools-scm
    pip3 install -r requirements.txt


USAGE
============

add comment to a packet of pcapng file


    python3 pcap_commentator.py write -i sample.pcapng -o out.pcapng -n 11 -c "TEST COMMENT"

Read comment from a packet of pcapng file


    python3 pcap_commentator.py read -i sample.pcapng -n 11