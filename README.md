# A CICS Transaction That Tracks Its Own CPU Usage
How can a CICS transaction measure its own CPU consumption while it is executing?  This has always been a challenge.  Even in the old days, when CICS transactions did
their processing on a single TCB - the quasi-reentrant (QR) TCB, measures like "elapsed time" or "CPU consumed by the QR TCB" were unreliable indicators of an individual transaction's CPU
usage.  At best, they provided an upper limit on the true value.  In the modern CICS world, with transaction processing potentially jumping around between multiple TCBs, the picture is even more complex.  Traditionally, the only source of reliable CPU usage information for a transaction comes 
from SMF type 110 subtype 1 "performance" records, which are written periodically (for long-running transactions) and at transaction termination.  These records are historical
by their nature and they are not available to the running transaction.

However, if CICS monitoring is enabled and performance class data is being collected, it is possible for a transaction to access the data which CICS is collecting, in real time.  The CICS System Programming Interface (SPI) command, `COLLECT STATISTICS`, provides this capability (see: https://www.ibm.com/docs/en/cics-ts/6.1?topic=commands-collect-statistics), but there are some considerations which apply to embedding this command in our application:
1. This command is fairly "heavy", which is to say, it affects the experiment.  Hence, we will need a way of measuring the CPU overhead of this command, so we can subtract its overhead from the CPU consumption for the processing we are actually interested in measuring.
2. CICS doesn't update performance statistics continuously, as each CICS command is executed.  Only certain CICS commands reliably trigger an update of the progressive totals of CPU usage and other counters.
3. Monitoring of performance class statistics may not be active in the CICS region when/where our transaction is executing, so we need to account for this and gracefully "do without" a CPU usage measurement, if it is not available.
4. Dozens of other statistics and parameters can be accessed by a running transaction using `COLLECT STATISTICS`, but as a rule, it will always be more efficient and reliable to use a conventional CICS API command (e.g. `ASSIGN`) to retrieve this information, where possible.

To cause CICS (more precisely, the CICS dispatcher) to update its running total of CPU usage for our transaction, we can use the `DELAY INTERVAL(0)` command[^1] (see: https://www.ibm.com/docs/en/cics-ts/6.1?topic=summary-delay).  This command is relatively "benign" (and it is "threadsafe") - it won't affect the state of any resources being manipulated by our transaction.

To measure the CPU overhead of `COLLECT STATISTICS` (and `DELAY INTERVAL(0)`), we can produce a reasonable estimate by calling this pair of commands twice in succession and measuring the difference in the CPU usage statistic.  To collect CPU usage statistics for our running transaction, we call `COLLECT STATISTICS` with the `MONITOR` clause, passing the `EIBTASKN` (i.e. task number) from the EXEC Interface Block (EIB) passed to our program by CICS.  The pointer returned by the `SET` clause of `COLLECT STATISTICS MONITOR(task)` is a DFHMNTDS structure, for which mappings are provided for Assembler (in library, _cicshlq_.SDFHMAC), C (in _cicshlq_.SDFHC370), COBOL (in _cicshlq_.SDFHCOB) and PL/I (in _cicshlq_.SDFHPL1).  Within the DFHMNTDS structure, the TMRCPUT "clock" field holds the total CPU time consumed (so far) for our transaction (general-purpose CP plus zIIP time).  There is a _smorgasboard_ of other CPU "clocks" available if we wanted to split out this value by CP versus zIIP, or by TCB (see: https://www.ibm.com/docs/en/cics-ts/6.1?topic=areas-mnt-transaction-monitoring-data).

CICS monitoring "clock" fields require some explanation.  Each "clock" field is 12 bytes, comprising a 64-bit integer "timer" in STCK format (8 bytes), a "reserved" portion (1 byte) and a 24-bit integer "period count" (3 bytes) (see: https://www.ibm.com/docs/en/cics-ts/6.1?topic=data-clocks-time-stamps).  To convert the "timer" value to units of seconds, divide it by 4,096,000,000.  In the case of the TMRCPUT field, the "timer" value is total CPU time and the "period count" value is the number of times the transaction has been dispatched (on any TCB).  If you access the "period count" as a 32-bit integer (including the "reserved" byte in the high-order 8 bits), make sure that you mask out the "reserved" bits - don't assume they are all zero.

Now we have all the information we need in order to add CPU usage measurement to our CICS programs.  Here is an example of a C program that measures the CPU time consumed by generating an AES-256 symmetric encryption key then using it to encipher 8KB of random data:

```
/* CICS program to measure CPU cost of AES key generation and encryption */

/*
 * To compile:
 *
 * $ cp "//'DFH550.CICS.SDFHLOAD(DFHELII)'" dfhelii.o           (do this once)
 * $ xlc -F xlc.cfg -o "//'MY.CODE.PDSE(GETCPU)'" \
 *       -I "//'SYS1.SIEAHDR.H'" -I "//'DFH550.CICS.SDFHC370'" \
 *       -qcics=sp -qfloat=afp getcpu.c dfhelii.o -l "//'CSF.SCSFSTUB'"
 *
 * xlc.cfg is a copy of default compiler config file, /usr/lpp/cbclib/xlc/etc/xlc.cfg
 * with STEPLIB added for CICS SDFHLOAD:
 *
 *    steplib           = CBC.SCCNCMP:DFH550.CICS.SDFHLOAD
 */

#define _LARGE_TIME_API         /* for gettimeofday64() */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "csfbext.h"            /* for ICSF CCA functions */
#include "dfhmntds.h"

int main(void)
{
    dfhmntds            *ptds;
    int64_t             timer1, timer2, timer3, overhead, cpucost;
    struct timeval64    tod1, tod2;
    int32_t             bufferLength = 8192;     /* 8KB buffers */
    uint8_t             *clearText, *cipherText;

    int32_t             return_code, reason_code, exit_data_length, rule_array_count,
                        reserved_length, random_number_length, key_identifier_length,
                        key_parms_length, block_size, initialization_vector_length,
                        chain_data_length, clear_text_length, cipher_text_length,
                        optional_data_length;
    uint8_t             exit_data[1], *rule_array, reserved[1], *random_number,
                        *key_form, *key_length, *key_type_1, *key_type_2,
                        KEK_key_identifier_1[64], KEK_key_identifier_2[64],
                        generated_key_identifier_1[64], generated_key_identifier_2[64],
                        *key_identifier, key_parms[1], initialization_vector[16],
                        chain_data[32], *clear_text, *cipher_text, optional_data[1];

    /* get EIB passed by CICS */
    EXEC CICS ADDRESS EIB(dfheiptr);

    /* get an initial measurement of CPU usage */
    EXEC CICS DELAY INTERVAL(0);
    EXEC CICS COLLECT STATISTICS SET(ptds) MONITOR(dfheiptr->eibtaskn);
    /* store CPU usage, taking account of the fact that monitoring may be disabled */
    timer1 = -1L;
    if (dfheiptr->eibresp == 0) {
        memcpy(&timer1, ptds->tmrcput.tmrcput_time, 8);
    }

    /* take a second measurement of CPU usage to estimate overhead of the measurement process */
    EXEC CICS DELAY INTERVAL(0);
    EXEC CICS COLLECT STATISTICS SET(ptds) MONITOR(dfheiptr->eibtaskn);
    /* store CPU usage, taking account of the fact that monitoring may be disabled */
    timer2 = -1L;
    overhead = -1L;
    if (dfheiptr->eibresp == 0) {
        memcpy(&timer2, ptds->tmrcput.tmrcput_time, 8);
        if (timer1 >= 0L) {     /* first measurement was successful */
            overhead = timer2 - timer1;
        }
    }

    /***********************************************************/
    /* Start of work for which CPU usage measurement is sought */
    /***********************************************************/

    /* take an initial elapsed time measurement */
    gettimeofday64(&tod1, NULL);

    /* allocate a buffer to hold random cleartext */
    EXEC CICS GETMAIN SET(clearText) FLENGTH(bufferLength);
    /* allocate a buffer to hold ciphertext */
    EXEC CICS GETMAIN SET(cipherText) FLENGTH(bufferLength);

    /* generate random cleartext using CSNBRNGL */
    exit_data_length     = 0;
    rule_array_count     = 1;
    rule_array           = "RANDOM  ";
    reserved_length      = 0;
    random_number_length = 8192;
    random_number        = clearText;
    CSNBRNGL(
        &return_code,
        &reason_code,
        &exit_data_length,
        exit_data,
        &rule_array_count,
        rule_array,
        &reserved_length,
        reserved,
        &random_number_length,
        random_number);
    if (return_code > 0) {
        printf("CSNBRNGL rc=%d, reason=%d\n", return_code, reason_code);
    }

    /* generate an AES-256 random encryption key */
    exit_data_length = 0;
    key_form         = "OP  ";
    key_length       = "KEYLN32 ";
    key_type_1       = "AESDATA ";
    key_type_2       = "        ";
    memset(KEK_key_identifier_1, 0x00, 64);
    memset(KEK_key_identifier_2, 0x00, 64);
    memset(generated_key_identifier_1, 0x00, 64);
    memset(generated_key_identifier_2, 0x00, 64);
    CSNBKGN(
        &return_code,
        &reason_code,
        &exit_data_length,
        exit_data,
        key_form,
        key_length,
        key_type_1,
        key_type_2,
        KEK_key_identifier_1,
        KEK_key_identifier_2,
        generated_key_identifier_1,
        generated_key_identifier_2);
    if (return_code > 0) {
        printf("CSNBKGN rc=%d, reason=%d\n", return_code, reason_code);
    }

    /* encipher the cleartext using the AES-256 key */
    exit_data_length             = 0;
    rule_array_count             = 4;
    rule_array                   = "AES     CBC     KEYIDENTINITIAL ";
    key_identifier_length        = 64;
    key_identifier               = generated_key_identifier_1;
    key_parms_length             = 0;
    block_size                   = 16;     /* for AES */
    initialization_vector_length = block_size;
    memset(initialization_vector, 0x00, initialization_vector_length);
    chain_data_length            = 32;
    clear_text_length            = bufferLength;
    clear_text                   = clearText;
    cipher_text_length           = bufferLength;
    cipher_text                  = cipherText;
    optional_data_length         = 0;
    CSNBSAE(
        &return_code,
        &reason_code,
        &exit_data_length,
        exit_data,
        &rule_array_count,
        rule_array,
        &key_identifier_length,
        key_identifier,
        &key_parms_length,
        key_parms,
        &block_size,
        &initialization_vector_length,
        initialization_vector,
        &chain_data_length,
        chain_data,
        &clear_text_length,
        clear_text,
        &cipher_text_length,
        cipher_text,
        &optional_data_length,
        optional_data);
    if (return_code > 0) {
        printf("CSNBSAE rc=%d, reason=%d\n", return_code, reason_code);
    }

    /* free buffers */
    EXEC CICS FREEMAIN DATAPOINTER(clearText);
    EXEC CICS FREEMAIN DATAPOINTER(cipherText);

    /***********************************************************/
    /*  End of work for which CPU usage measurement is sought  */
    /***********************************************************/

    /* take a final elapsed time measurement */
    gettimeofday64(&tod2, NULL);

    /* take a third measurement of CPU usage to estimate CPU usage for the above work */
    EXEC CICS DELAY INTERVAL(0);
    EXEC CICS COLLECT STATISTICS SET(ptds) MONITOR(dfheiptr->eibtaskn);
    /* store CPU usage, taking account of the fact that monitoring may be disabled */
    timer3 = -1L;
    cpucost = -1L;
    if (dfheiptr->eibresp == 0) {
        memcpy(&timer3, ptds->tmrcput.tmrcput_time, 8);
        if (timer2 >= 0L) {     /* second measurement was successful */
            cpucost = timer3 - timer2;
            /* subtract the measurement overhead, if it could be measured */
            if (overhead >= 0L) {
                cpucost -= overhead;
            }
        }
    }

    printf("Elapsed time: %.6f s  CPU time: %.6f s  MOH time: %.6f s\n",
           ((double)(tod2.tv_sec - tod1.tv_sec)) + ((double)(tod2.tv_usec - tod1.tv_usec)) / 1000000.0,
           cpucost  > 0L ? ((double)cpucost) / 4096000000.0 : 0.0,
           overhead > 0L ? ((double)overhead) / 4096000000.0 : 0.0);

    /* return to CICS */
    EXEC CICS RETURN;

    return 0;
}
```
Here is the output, written to the CICS region's log, from a single execution of this program:
```
0018GCPU 20220707210141 Elapsed time: 0.003405 s  CPU time: 0.001037 s  MOH time: 0.000123 s
```
Notice that the CPU time is significantly less than the elapsed time.  The "MOH time" is the CPU time consumed between two consecutive executions of `DELAY INTERVAL(0)` and `COLLECT STATISTICS MONITOR(task)`, giving an estimate of the "measurement overhead".

[^1]:  I need to give a shout-out to Ian Burnett at IBM Hursley Labs for pointing me at `DELAY INTERVAL(0)` as the best way to force the CICS dispatcher to update the current trasnaction's statistics.
