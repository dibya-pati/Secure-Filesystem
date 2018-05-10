# .bashrc

# User specific aliases and functions

alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias cdsgfs='cd /usr/src/hw3-cse506g03/fs/sgfs/'
alias cdhw3='cd /usr/src/hw3-cse506g03/hw3/'
alias cdmnt='cd /mnt/sgfs/.sg/'
alias lsmnt='ls -alh /mnt/sgfs/.sg/'
alias rmsg='umount /mnt/sgfs;rm -rf /usr/src/hw3-cse506g03/hw3/mnt-sgfs/.sg /usr/src/hw3-cse506g03/hw3/mnt-sgfs/.keyring /usr/src/hw3-cse506g03/hw3/mnt-sgfs/.metadata;rm -f /usr/src/hw3-cse506g03/hw3/mnt-sgfs/rnd*;rm -f /mnt/sgfs/rnd*'
alias dm='dmesg -L'

# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi
