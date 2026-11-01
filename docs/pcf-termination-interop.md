# PCF termination callback with OAuth enabled
Use the paired PCF and NEF fix/1207-nef-termination-oauth branches. NEF
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
