# minIFF: a proof of concept for a secure drone-oriented IFF solution

*Disclaimer: The idea for minIFF stems from a hackathon organized by the French war college (Ecole de Guerre). However, this work is not affiliated with the Ecole de Guerre, the French Ministry of Armed Forces, nor represents their positions in any sort.*

UAVs are now everywhere: shootings, races, visual shows, geographic studies, agriculture, and, as we have seen in the middle East and in Ukraine, war. This democratization of the use of aerial drones comes with new threats and requirements. One of them is being able to identify friendly drones in a secure and reliable way.

Secure IFF solutions already exist: IFF modes 4 (well, it is no longer considered secure nowadays) and 5 have been standardized by NATO. The problem is that the equipment needed to run these systems are outrageously expensive and way too big to be embedded on a small drone. Also, they require you to be part of a governmental organization, due to the export control enforced over those systems.

This whitepaper proposes an IFF protocol that can be easily implemented and used over cheap consumer hardware, while retaining a high level of security. As such, it follows a few general principles:

1. Highest possible level of security and reliance on modern standardized cryptography: AES-GCM/ChaCha20-Poly1305, Curve25519-based algorithms, Blake2/SHA-2
2. Adaptability to different wireless physical layers: LoRA chips, CC1101 transmitters, mesh-networks, …
3. Ability to run on low power embedded devices: ESP32-like chips
4. Limitation of network traffic in order to prevent detection and localization
5. Resistance to the compromise of a lost drone

## Interrogation process

As for regular IFF systems, minIFF uses an interrogator-responder principle: an interrogator device sends a challenge to the surrounding drones, which all answer with a message containing their location. Note that, in principle, the interrogator could “focus” the interrogation process by using directive antennas, but that is beyond the scope of this paper.
The main issue here is threefold:
We want the transmissions to be encrypted, using perfect forward secrecy (requirement 5)
Given requirement 4, there is no reasonable way to keep a synchronized channel between the interrogator and the responder as the radio channel can be inadvertently cut or adversarially jammed (hence messages lost), and do not want to emit non-stop. Also, we do not want to (and sometimes just cannot) rely on an external clock (requirement 3).
The interrogator cannot create a channel for every possible responder, in particular because it does not necessarily know which ones are expected to answer its challenge. As such, it needs to broadcast a ubiquitous challenge, which will then be answered differently by every responder.
As such, we need to rely on single roundtrip communication from the interrogator to the responder with broadcast capabilities. A good starting point to find best-in-class secure communication protocols is to look at the [Noise specification](https://noiseprotocol.org/noise.html) and the different handshake patterns it proposes. This allows us to easily meet the first general principle.
We need to look for patterns for which the key of the initiator (in our case the interrogator) is known to the responder (patterns beginning with a K), and the responder’s key is transmitted to the initiator (patterns ending with and X). This gives us the KX pattern, which is as follows:

```
KX:
    -> s
    ...
    -> e
    <- e, ee, se, s, es, payload
```

Let us recall what the semantic of the Noise notation is. The first line means that the interrogator’s static public key has been pre-sent to the responder. For the interrogation process, the interrogator sends an ephemeral public key (-> e), which is responded to with the responder public ephemeral key, whose private part is combined (using Diffie-Helmann) with the interrogator’s ephemeral and static public keys (<- e, ee, se). Using these two DH values, the public static key of the responder is sent ([…], s, […]) and itself combined with the interrogator’s ephemeral key (es) to be used to encrypt the payload.

As mentioned in Section 7.7 of the Noise specification, this exchange pattern provides the best security guarantees from the set of proposed patterns: resistance to key-compromised impersonation, and strong forward secrecy. Still, let us take a look at possible attacks and improvement we can bring.

### Attacks

The general setting of our IFF is a bit different from the one used in the Noise framework. As an example, the Noise authors do not worry about a responder sending an answer to a message not initiated by a legitimate initiator. Indeed, the key exchange patterns they present aim at securing the transmitted information, not at avoiding unneeded responses.

#### Rogue interrogator attack

Imagine that the attacker wants to use direction finding to locate your drone implementing minIFF. He could try to send adversarial interrogation message at a high frequency to trigger responses from the drone and use these frequent emissions with a direction finder. 
Thus, we must ensure that the messages the drone responds to originate from the interrogator. The easiest solution to this requirement is to use a simple signature on the first message of the exchange. The responder, knowing the signing public key of the interrogator, will be able to check the signature and answer only if it is correct. So, the new protocol looks like this (s_sig being the signature’s public key, and sig the signature of the first message):

```
-> s, s_sig
...
-> e, sig
<- e, ee, se, s, es, payload
```

#### Replay attacks

Unfortunately, the attacker could record the first message of the interrogator and replay it multiple times to perform a similar attack as the one described earlier. Yet, the drone cannot reasonably keep track of all the previously received messages (remember principle 3). However, we can use a well-known technique here: increasing counters.
The interrogator increments a counter every time it does a new interrogation. The counter is sent in the first message. The responder now just has to check that the counter of the challenge he just received is larger than the one of the previous challenge. If it is not the case, he can treat the challenge as a replay attack and dismiss it.
The counter can also be included inside the drone’s response. That way, the interrogator prevents the attacker from being able to replay an old challenge’s response (and prevent to interrogator to believe that the drone is at the same location as the one he was at 10 minutes earlier). It also allows to implement a timeout mechanism, in which the interrogator can dismiss responses deemed too old.
This new protocol looks like this (we omitted the initial sharing of the interrogator’s static keys).
```
-> e, counter, sig
<- e, ee, se, s, es, counter, payload
```


#### Impersonation attacks

In our setting, we cannot rely on the guarantee that the physical layer on which this protocol runs provides the “address” (i.e. the identity) of the responder. This information is important to correctly associate the location’s coordinates with the drone itself, and needs to be sent by the responder.
Also, we need to have a trustworthy way to bind a drone id with its static public key. There are essentially two ways of doing that:

- Providing the interrogator with a table of these associations;
- Using a lightweight public key infrastructure.

In practice, it means in both case that the drone’s user has to register its drone/static public key before flying. The only difference lies in the way the public key is distributed. In the second case, it is by the drone itself, while in the first, it this through another unspecified mean (e.g. a central server or through direct drone registration to the interrogator).

However, not relying on a PKI has the big upside of reducing the responder’s message size. First because, we avoid having to send the 64 bytes of the signature (in case we are using Ed25519), but also because instead of sending the public key itself, we can just send the drone id which will be then used to retrieve the key. If we take a 4 bytes-long id (i.e. able to support $2^{32}$ drones, more than 4 billion), we save 32-4 = 28 bytes (in the case of a X25519 key). This is a big saving, knowing that, for many radio protocols, the maximum message length is 255 bytes.

We end up with the following protocol

```
-> s, s_sig
<- id, s
...
-> e, counter, sig
<- e, ee, se, id, es, counter, payload
```

We explicitly mentioned the registration step by the `id, s` statement (although we are slightly departing from Noise specification’s notation here). Note that, in the last message, id has to be sent before computing the interrogator ephemeral-responder static Diffie-Hellman and using it for payload encryption: otherwise, the interrogator would not be able to retrieve the key from the id.

## Implementation

This protocol has been implemented in C++ over two types of radios, C1101 and LoRA, LoRA beeing the right choice given its range. Both implementations can be found in the [minIFF GitHub repository](https://github.com/rbost/minIFF).

The LoRA implementation, was tested over an Heltec v3 LoRA ESP32 board and a small antenna. In this setting, on the ground and in an urban environment, a range of 250 meters was reached without issue. This is still unsatisfactory, but it is believed that, in a less strigent setting, with both the interrogator and the responder being airborne, a range of one kilometer could easily be reached.
