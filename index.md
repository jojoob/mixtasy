## What is Mixtasy?
Mixtasy is a remailer protocol that aims to provide good security and anonymity for emailing on top of existing infrastructure.
The protocol is described in the Master's Thesis "Mixtasy: Remailing on Existing Infrastructure - Anonymized Email Communication Easily Deployable Using SMTP & OpenPGP" by Johannes Burk.
There is also a prototypical implementation ([available on GitHub](https://github.com/jojoob/mixtasy/)) of a feature subset of the protocol to demonstrate the feasibility.

More information about remailers in general and existing remailer protocols and software can be found here:

* [Wikipedia: Anonymous remailer](https://en.wikipedia.org/wiki/Anonymous_remailer)
* [crypto.is blog: What is a Remailer?](https://crypto.is/blog/what_is_a_remailer)
* [crypto.is blog: Remailers We've Got](https://crypto.is/blog/remailers_weve_got)
* [Mixmaster Remailer Website](http://mixmaster.sourceforge.net/)
* [Mixminion Remailer Website](http://mixminion.net/)

## Mixtasy Prototype
A prototype which implements a subset of the Mixtasy remailer specification written in python can be found on [GitHub](https://github.com/jojoob/mixtasy/).
This implementation can be used for the creation and sending of Mixtasy messages and to setup a Mixtasy mix node.
Details are explained in the [README.md](https://github.com/jojoob/mixtasy/blob/master/README.md) file within the repository.

## Test Network
There are currently three Mixtasy mixes available for testing purposes:
They are explicitly not for production use and their continuous availability is not guaranteed.

* [Online] 1.alphatest.mixtasy.net
* [Online] 2.alphatest.mixtasy.net
* [Online] 3.alphatest.mixtasy.net

The PGP keys for the test servers can be found here: [pgp.mit.edu key search](http://pgp.mit.edu/pks/lookup?search=alphatest.mixtasy.net)

To send a Mixtasy test message download or clone the prototype from GitHub and invoke the Mixtasy python script as follows:
```sh
./mixtasy.py create -m 1.alphatest.mixtasy.net -s username@your-mail-provider.com
```
You have to enter a mail including at least a "To:" mail header line to indicate the receiver of the message. The message body must be separated from the header with a blank line.
For example:
```
To: bob@example.com
Subject: Just a Mixtasy test message

Hi Bob, it's me.
```

**Please,** only use the listed mix nodes for testing purposes. Try to not cause high load.

**Note:** The test nodes are currently not able to deliver mails to the most big mail providers (including gmail, gmx, etc.). Maybe use your own mail server for testing.

## Theory
Mixtasy: Remailing on Existing Infrastructure  
Anonymized Email Communication Easily Deployable Using SMTP & OpenPGP

[Complete master's thesis](res/Mixtasy-Masters_Thesis-Johannes_Burk.pdf)  
[Slides from the Presentation at the Austrian Young Researchers' Day](res/Mixtasy-YRD_2016-Presentation.pdf)

### Abstract
Email is one of the oldest electronic communication tools.
While it provides excellent service in terms of simplicity and reliability, it suffers from high insecurities and does not provide any anonymity or privacy.
Even the increasing use of known transport and end-to-end encryption techniques cannot avoid leaving a trace of metadata.
Several existing solutions try to tackle these weaknesses, but non of them fit all requirements (including usability and adoption properties) regarding secure and anonymized communication.

Thus, this work develops 'Mixtasy', a new protocol based on a mix network.
In order to enable rapid deployment, which facilitates better anonymization in this class of protocols, a central design goal was easy adoption.
This is achieved by reusing existing technologies (OpenPGP, SMTP, Internet Message Format) and infrastructure (PGP key servers, mail transfer infrastructure).
The practicability of the protocol is proven by a prototypical implementation.
While excluding mixing algorithms and dummy traffic, the prototype offers basic anonymization of email communication.
A complete implementation of the specification for protection against global adversaries is outstanding.
Possible improvements, especially the optimization of the used mixing algorithm and enabling anoynmous replies, are discussed and outlined for future work and research.
