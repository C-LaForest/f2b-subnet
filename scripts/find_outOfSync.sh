#!/bin/bash
echo '*** JAIL:dovecot ***'
diff <(fail2ban-client get dovecot banip --with-time | grep -oP '(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?' | sort) \
     <(nft list set inet f2b-table addr-set-dovecot | grep -oP '(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?' | sort)
echo '*** JAIL:dovecot-subnet ***'
diff <(fail2ban-client get dovecot-subnet banip --with-time | grep -oP '(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?' | sort) \
     <(nft list set inet f2b-table addr-set-dovecot-subnet | grep -oP '(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?' | sort)
