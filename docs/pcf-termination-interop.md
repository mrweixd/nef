# PCF termination callback with OAuth enabled
Use PCF commit `920a05d5c9a00ad0dfb475bc1455366fdb5494ac` and the NEF
`fix/callback-operation-authorization` branch. NEF
must advertise nnef-callback in its NRF profile. PCF discovers the registered
NEF API prefix and requests an instance-targeted token for that service.
The callback is consumed by NEF and is not forwarded to the AF.

From a directory containing the two repositories as pcf/ and nef/:

    go -C pcf test -race -c -o /tmp/pcf-termination.test ./internal/sbi/processor
    PCF_INTEROP_TEST_BIN=/tmp/pcf-termination.test go -C nef test -race -count=1 -v ./internal/sbi -run '^TestPCFTerminationInterop$'

The test runs both production callback paths over loopback HTTP with an NRF
discovery/token fixture and signed JWTs. It checks 401 for the former scope and
a different audience, and 204 plus removal of the bound subscription for the
PCF request. It does not start a full core or validate NRF deployment policy.

With OAuth enabled, NEF also resolves the verified bearer subject via its own
configured NRF (nnrf-disc). The SMF event and PCF termination routes require
a REGISTERED profile with that exact instance ID and the corresponding NF type.
The shared nnef-callback scope alone is insufficient. Discovery is performed
for each valid callback payload before its handler can change subscription
state or forward an event. Unknown callers and role mismatches return 403;
an unavailable registry returns 503 without performing the operation.
OAuth-disabled behavior is unchanged.

Run the bidirectional operation and side-effect checks with:

    go -C nef test -race -count=1 -v ./internal/sbi -run '^TestCallbackOperationAuthorization$'
