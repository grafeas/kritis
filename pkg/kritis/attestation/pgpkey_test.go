/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package attestation

import (
	"testing"

	"github.com/grafeas/kritis/pkg/kritis/testutil"
)

func TestPgpKey(t *testing.T) {
	// Generate keys for test@pgp.com
	const private = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG C# v1.6.1.0

lQOsBFv+Y7UBCADGf1/XErc1VjjakMwI5kJumfS+FpzFhIq9MsdzoOOD+o+q7Noj
0r5Y4acp9AGvA0fA7H15JdyT4DEEcNzUNyQySV/Huto0NT5t1L8JLI70/RhF38LA
kdSR+Q7Uhf/7+6zTB0nfRnc2nfp24PvWSuUlP8NsgUA6WCFY70w6S2iNnv0WsiLU
XoHpdPm1ke3LABfc5Ujv/4V38WrGb17RP9y3J1TS7TG9tb4ndAIOSEIoxB2njVp1
B76ZZWD6WbDxAr4V8X5CBEwyDV4mUE3fcouZXeOgFw5WoLIC14Q3YY1zOoS1SOCY
0joJZTFfoAlWYorbG4XREcSsSodsvEOFjLInABEBAAH/AwMC2dqsriFMWglgurJl
xHcugu8aqD9i2lPLnSGZyRNV9Wu3Uhwjj0ROTjVm7mcTwxaCEtk9UfzfIZ67SFmn
EFze8ZmNaOvlRNkwAOa3TtJbGuHA27HQyzlcRZ2lqYl9ABkUEj1hDrkk7lDN7qml
QA3JP3UCsuFwwSyBOp2XbbLBYAj/wgvJ/K3HaCp0xHHnQofAgROV1ccZXjIgwknh
iEx3cW7ga4LSVsC0U9gulOeOu4DjSohyP+NC+fE658VTYJvQ0NJoMhGaewqLskye
wjbSD1ZCABCW5GrgsJv/cqrA8EFehGXJVNCZWiW0w1kXMV+Lk60ZA12WycHYyVSi
3tvZtkj0VZc36TtEYp7YLkzsYVXgtVJOn0GfwYRUqxcI5nVqP2sv/uQ3h9PMvpo7
DRLxn8d/e9fwT4Cbxf0wQcu4T07QP0Nwi4btfDb4HeaiiKK8uoSZjUg542Ts42bN
iGiQ2eer0bU/gcH6LvczlQMXTuUfeZvrxf9h1djwZwKmi926vIGYFE96J+w9xwsz
hgSrONnDoj1ciKiRANBLV6ddDWiTNm4FQZAR1FZIrHwrzb34cJPEQvGI3yJfWVIS
ZmkELKF6W4d1e3lMsKneZJCD0ZI8uhb7m3flj1bx4NzJshmPDrw3/Zw6J7xZnL78
Yf6FtjYvdHifueYpIgt1IqvnjDrlBT57FRWwUlV/EP6hORylq2byEOJDT9NGJR9r
EuaHQGQTdLn6yeDaUOrLq7ei+O+3qU9+5ztpgTpvjgUiOpgbAQ2K13882YHjnG7k
l2JlEsLKZLfov5pbhpW4wzWIByfzSjCcSCW5jfRpxu0tkheX3dCm5/BaPXgPnHtN
8t/5x3gWhojEeF4mBB0EiemIRIO3zMh6rfZuiqNMo7QMdGVzdEBwZ3AuY29tiQEc
BBABAgAGBQJb/mO1AAoJEDbFvgxBN1W2do0IAKFb2YcATgHg/h3HaV2NKnwY2+qf
BrvMifI964XOe+KUsUn8lzdKdO/HqgaAY8pwtnWi/ZIKKwEmFLUJ4nnw5KCOYANH
98br3JLVXolSJET3HVQjLO66dqBwnxfRBE+RodI/xgN3hhKpY80TmSCV4c+8ZS9K
uk1OYjmhy7o41Uythm3JZtlVWaQwNrxuW8FZaKf+ddAunVpYdAxyGIvQOeSvvjT8
wS/ESDp9/HoTDeQ/xj2yTr7taoZNnNDe1WrQueqE/kHpB3+a6jsdfMmduP7KCk1c
SfFhCkm3GY7opmHqvdkoBSpk7DwEmao+Q3frLO7EFr8EZ4o8PfFay4+QMFM=
=zZoX
-----END PGP PRIVATE KEY BLOCK-----`
	const public = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG C# v1.6.1.0

mQENBFv+Y7UBCADGf1/XErc1VjjakMwI5kJumfS+FpzFhIq9MsdzoOOD+o+q7Noj
0r5Y4acp9AGvA0fA7H15JdyT4DEEcNzUNyQySV/Huto0NT5t1L8JLI70/RhF38LA
kdSR+Q7Uhf/7+6zTB0nfRnc2nfp24PvWSuUlP8NsgUA6WCFY70w6S2iNnv0WsiLU
XoHpdPm1ke3LABfc5Ujv/4V38WrGb17RP9y3J1TS7TG9tb4ndAIOSEIoxB2njVp1
B76ZZWD6WbDxAr4V8X5CBEwyDV4mUE3fcouZXeOgFw5WoLIC14Q3YY1zOoS1SOCY
0joJZTFfoAlWYorbG4XREcSsSodsvEOFjLInABEBAAG0DHRlc3RAcGdwLmNvbYkB
HAQQAQIABgUCW/5jtQAKCRA2xb4MQTdVtnaNCAChW9mHAE4B4P4dx2ldjSp8GNvq
nwa7zInyPeuFznvilLFJ/Jc3SnTvx6oGgGPKcLZ1ov2SCisBJhS1CeJ58OSgjmAD
R/fG69yS1V6JUiRE9x1UIyzuunagcJ8X0QRPkaHSP8YDd4YSqWPNE5kgleHPvGUv
SrpNTmI5ocu6ONVMrYZtyWbZVVmkMDa8blvBWWin/nXQLp1aWHQMchiL0Dnkr740
/MEvxEg6ffx6Ew3kP8Y9sk6+7WqGTZzQ3tVq0LnqhP5B6Qd/muo7HXzJnbj+ygpN
XEnxYQpJtxmO6KZh6r3ZKAUqZOw8BJmqPkN36yzuxBa/BGeKPD3xWsuPkDBT
=4l+X
-----END PGP PUBLIC KEY BLOCK-----`
	key, err := NewPgpKey(private, public)
	testutil.CheckError(t, false, err)
	if key == nil {
		t.Fatalf("Got nil key")
	}
	if key.publicKey == nil {
		t.Fatalf("Got nil public key")
	}
	if key.privateKey == nil {
		t.Fatalf("Got nil private key")
	}
}
