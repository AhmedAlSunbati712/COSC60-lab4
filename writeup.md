## Part 1: Search and Rescue

### Monitor Mode

- Research and describe what monitor mode is.

- In your write-up, describe why setting the channel is important.

- Provide terminal output from your script showing it successfully set monitor mode.

### Beacon Design

- Describe what information your beacon contains that would help rescuers.

- Describe when/how often you will transmit these beacons.

- Discuss the idea of using RSSI as a proxy for distance and give examples of where it could go wrong.

- Is RSSI a good proxy for distance in this rescue use case?

## Part 2: Secret Key Exchange

### Calculate a key on each device 

- Discuss reasonable values for z (the number of standard deviations).

At first we started with relatively low (.75) values for z because we didn't want too many bits to be dropped, but we ended up having to go all the way up to 1.8 for the sake of consistency. The downside is of course much shorter keys.

- Describe how bits should be included in a cryptographic key that will serve as a basis for long-term secure communication.

The bits from this lab aren't enough for a decent cryptographic key, but perhaps they could be used to seed key generation for both parties or to temporarily encrypt communication in order to store better long-term keys.


- Show evidence both devices independently computed the same key.

#### Initiator

![](./img/initiator.png)

#### Responder

![](./img/responder.png)
