# ParticipantVolatileMessageSecure Handling

## Short Introduction

It is expected to have some knowledge of DDSI builtin (security) endpoints.

```cpp
#define NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_WRITER 0xff0202c3
#define NN_ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_SECURE_READER 0xff0202c4
```
These builtin endpoints have caused about the biggest code change in ddsi, regarding security.

Chapters 7.4.4.3 and 7.4.4.4 in the DDS Security specification indicates the main issue why these builtin endpoints are different from all the others and somewhat more complex.

> 7.4.4.3 Contents of the ParticipantVolatileMessageSecure
> The ParticipantVolatileMessageSecure is intended as a holder of secure information that
> is sent point-to-point from a DomainParticipant to another.
>
> [...]
>
> 7.4.4.4 Destination of the ParticipantVolatileMessageSecure
>
> If the destination_participant_guid member is not set to GUID_UNKNOWN, the message written is
> intended only for the BuiltinParticipantVolatileMessageSecureReader belonging to the
> DomainParticipant with a matching Participant Key.
>
> This is equivalent to saying that the BuiltinParticipantVolatileMessageSecureReader has an implied
> content filter with the logical expression:
>
> “destination_participant_guid == GUID_UNKNOWN
> || destination_participant_guid==BuiltinParticipantVolatileMessageSecureReader.participant.guid”
>
> Implementations of the specification can use this content filter or some other mechanism as long as the
> resulting behavior is equivalent to having this filter.
>
> [...]

The "point-to-point" and "content filter" remarks makes everything more elaborate.


## Complexity

It would be nice to be able to use the ```dds_set_topic_filter()``` functionality for these endpoints. However, that only works on the reader history cache (rhc), which is only available for ddsc entities and not for ddsi builtin entities. And it's the builtin entities that are being used.

The ```dds_set_topic_filter()``` basically simulates that the sample was inserted into the rhc (but didn't insert it), which causes the rest of ddsi (regarding heartbeat, acknacks, gaps, etc) to work as normal while the sample just isn't provided to the reader.

Unfortunately, the builtin volatile endpoints can not use that same simple sequence (just handle the sample but ignore it right at the end). Problem is, the sample is encoded. It can only decode samples that are intended for that reader. This would mean that it is best for the reader to only receive 'owned' samples that it can actually decode.

This has all kinds of affects regarding the heartbeat, acknacks, gaps, etc. Basically, every writer/reader combination should have information regarding gaps and sequence numbers between them, while normally such information about proxies are combined.


## Implementation Overview

This only depicts an overview. Some details will have been omitted.


### Writing

The function ```write_crypto_exchange_message()``` takes care of generating the right sample information and pass it on to ```write_sample_p2p_wrlock_held()```.

A proxy reader can now have a filter callback function (```proxy_reader::filter```). This indicates (on the writer side) if a sample will be accepted by the actual reader or not. This could be made more generic for proper 'writer side' content filter implementation. However, now it'll only be used by ParticipantVolatileMessageSecure and the filter is hardcoded to ```volatile_secure_data_filter()```.

So, if ```write_sample_p2p_wrlock_held()``` is called with a proxy reader with a filter, it will get 'send/acked sequences' information between the writer and proxy reader. This is used to determine if gap information has to be send alongside the sample.

Then, ```write_sample_p2p_wrlock_held()``` will enqueue the sample.

Just before the submessage is added to the rtps message and send, it is encoded (todo).


### Reading

First things first, the submessage is decoded when the rtps message is received (todo).

It is received on a builtin reader, so the builtin queue is used and ```builtins_dqueue_handler()``` is called. That will forward the sample to the token exchange functionality, ignoring every sample that isn't related to the related participant (todo).


### Gaps on reader side

The reader remembers the last_seq it knows from every connected proxy writer (```pwr_rd_match::last_seq```).
This is updated when handling heartbeats, gaps and regular messages and used to check if there are gaps.
Normally, the ```last_seq``` of a specific writer is used here. But when the reader knows that the writer uses a 'writer side content filter' (```proxy_writer::uses_filter```), it'll use the the ```last_seq``` that is related to the actual reader/writer match.
It is used to generate the AckNack (which contains gap information) response to the writer.


### Gaps on writer side

The writer remembers which sample sequence it send the last to a specific reader through ```wr_prd_match::lst_seq```.
This is used to determine if a reader has received all relevant samples (through handling of acknack).
It is also used to determine the gap information that is added to samples to a specific reader when necessary.


### Heartbeats

A writer is triggered to send heartbeats once in a while. Normally, that is broadcasted. But, when a proxy reader uses a content filter, it has to be send to each reader specifically.
This is indicated by ```writer::xmit_hb_p2p``` and each writer/proxyreader match contains heartbeat information (```wr_prd_match::hbcontrol```), which is is normally stored on a per-writer basis.

When a writer should send heartbeats, ```handle_xevk_heartbeat()``` is called. When ```xmit_hb_p2p``` is enabled, the control is immediately submitted to ```send_heartbeat_to_all_readers()```. This will add heartbeat submessages to an rtps message for every reader it deems necessary.


### Reorder

TODO: explain.

Comment from the code:
```cpp
    /* for the builtin_volatile_secure proxy writer which uses a content filter set the next expected
     * sequence number of the reorder administration to the maximum sequence number to ensure that effectively
     * the reorder administration of the builtin_volatile_secure proxy writer is not used and because the corresponding
     * reader is always considered out of sync the reorder administration of the corresponding reader will be used
     * instead.
     */
```
Why should the reader's reorder be used and not the proxy writer's?

</br>
</br>
</br>
</br>
</br>
</br>
</br>
</br>
</br>
</br>
</br>
=================================================</br>
Notes</br>
=================================================</br>

Trying to put the security participant volatile endpoint implementation into context.

What are these things used for?

//wr_prd_match::lst_seq;
//wr_prd_match::hbcontrol;

//pwr_rd_match::last_seq;

//writer::xmit_hb_p2p

//proxy_writer::uses_filter

//proxy_reader::filter

//writer_hbcontrol_p2p(): What does it do and who uses it?

nn_defrag_prune(): What does it do and who uses it?
nn_reorder_set_next_seq(): What does it do and who uses it?

//volatile_secure_data_filter(): What does it do and who uses it? It's on the proxy reader.

//handle_AckNack(): gaps handling when using filter. How? Why?

//handle_Heartbeat_helper(): last_seq depends on pwr::last_seq or pwr_rd_match::last_seq. What does that do?

//handle_Heartbeat(): When using filter, do some reordering dqueue_enqueue and set pwr_rd_match::last_seq instead of the complicated stuff. Why?

//handle_one_gap(): only defrag when not using filter.

//handle_Gap(): just set pwr_rd_match::last_seq

//handle_regular(): When using filter, do some reordering dqueue_enqueue and set pwr_rd_match::last_seq instead of the complicated stuff.

//send_heartbeat_to_all_readers(): What?

//handle_xevk_heartbeat() -> send_heartbeat_to_all_readers() when writer::xmit_hb_p2p is true.

//add_AckNack(): Basically, do out of order stuff when using filter (last_seq depends on pwr::last_seq or pwr_rd_match::last_seq).

//write_sample_p2p_wrlock_held



* Rebase to security branch, which now contains the other security endoints.
* Maybe fix <https://github.com/eclipse-cyclonedds/cyclonedds/pull/296#issuecomment-547822817>?
* Clean up code, especially when considering footprint when security support is not enabled.
* Improve document.
* Manual testing.
* In depth review.



