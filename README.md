# Mixtasy
Mixtasy - an openPGP based remailer

This is a prototype which implements a subset of the Mixtasy remailer specification written in python.
To setup a Mixtasy mix this repository contains a bash script which is meant to be used as a simple Postfix content filter (see http://www.postfix.org/FILTER_README.html).

## Requirements
* python 2.7
* fitted python module [python-gnupg](https://github.com/jojoob/python-gnupg) (fork of https://bitbucket.org/vinay.sajip/python-gnupg/)
* [GnuPG](https://gnupg.org/)

## Usage
For help on how to invoke the python program execute `mixtasy.py -h`

### Create a Mixtasy Message
To create a Mixtasy message just execute `mixtasy.py`.
The message (including header and body) will be read from stdin as long you specify an input file with the `-f` option.
The input must contain a `To:` header field which holds the final recipient of the message.
The created Mixtasy message ready to send to the first mix (specified in the `To:` header field of the outputted mix message) is printed to stdout unless you specify an output file with `-o`.

### Process/Unpack a Mixtasy Message
To unpack one layer of a Mixtasy message execute `mixtasy.py -u`
Like for the message creation command the `-f`/`-o` options can be used to specify files for input/output instead of using stdin and stdout.

## Setup a Mix
1. Setup a Postfix SMTP server
2. Create an user named 'mixtasy'
3. Create an openPGP key with the 'mixtasy' user for your mix node and publish it on a public openPGP keyserver.

    Note: The openPGP key must follow the Mixtasy protol specification.
4. Copy the `mixtasy.py` and `mixtasy-filter.sh` to a location the 'mixtasy' user has permissions to execute them.

    Note: Permissions granted via groups seems not to be considered.
5. Adjust the mix address in `mixtasy-filter.sh`
6. Change the value of the `MIXADDRESS` variable in the `mixtasy-filter.sh` script to the address of your Mixtasy mix (e.g. `mixtasy@mydomain.com`)
7. To define the Postfix Mixtasy filter service
    add the following block to your Postfix's `master.cf`

    /etc/postfix/master.cf:
    ```
    mixtasy    unix  -       n       n       -       10      pipe
      flags=Rq user=mixtasy null_sender=
      argv=/path/to/mixtasy-filter.sh -f ${sender} -- ${recipient}
    ```

8. To enable the Mixtasy filter
    add the `-o content_filter=mixtasy:dummy` option to the Postfix SMTP service.

    /etc/postfix/master.cf:
    ```
    smtp      inet  n       -       -       -       -       smtpd
      -o content_filter=mixtasy:dummy
    ```
