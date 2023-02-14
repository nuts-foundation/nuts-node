package tokenV2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEmptyAuthorizedKeys ensures an empty authorized_keys file is properly parsed
func TestEmptyAuthorizedKeys(t *testing.T) {
	keys, err := parseAuthorizedKeys([]byte(""))
	assert.Empty(t, keys)
	assert.Nil(t, err)
}

// TestDSAIgnored ensures a DSA key cannot be loaded
func TestDSAIgnored(t *testing.T) {
	authorized_keys := "ssh-dss AAAAB3NzaC1kc3MAAACBAPAYg+9y+SDrSwNN4BdhDrwzAtYgaIikV6uhfBO/S9+TnP1Zk2sjeUIa5Itg8yDhVD6L5TpHu9q5mLBkb7iKhYeSEw4u6c2XlFOAqWWVw9rOMsYk8kBZGYUocujhSQD+le/3eyLOvbzik6cs/xmqtfHLKqlfF4zy6YWV4srHlLbXAAAAFQDME+5DfP+qtbeJE+YMAx5755fUzQAAAIEAl9uplCfex6xAqnGxtPCAER/HTDq5glww59EQjulMPiIIfBLT5sAXgJEqs9Mf51zdZhI+wwSXX7xc7IipJ6DeOO2iCZITSDByOFVCgHdRNMoh5mtrdyUNPhcEOkJye/o+MkhQy6X01UmEKDBWl187B/1r5ztA9jFcHCUbx83pIa8AAACAd/dfGr42lN6Jwk1tUMw0/J2Ak2FGCWYvaJk/4AXYd8ipX6JrQUS6TbP+lYQIcETIVpdLlp4AMY8GEZ5A4K3Yg9rp6RhhSvz+f/w4RqAz8JoAe64SwpHQhqymecfAefIzMM+2PV5rxNdCxDzPFmCN1c5K1oiu0340lLl0S1gcDp4= dsa@test.local"
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Empty(t, keys)
}

// TestRSA1024Ignored ensures an RSA 1024-bit (weak) key cannot be loaded
func TestRSA1024Ignored(t *testing.T) {
	authorized_keys := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC3ToEcgzKf5wh6vymMUiyFkPTJXLol3zUcuyE5ZjJbzYKbOCTwQtTd9UaMR9APx4hYLAIzXvVXT76YswqRfgzJiY3ayVTdQsyGS5Wf3bXgP/mcI4SfdB3AHQZ5AMRsvnbxhf8cdg7IWLf+WtNOa58iaOrGUN4PDkRXfH5wPow17w== rsa-1024@test.local"
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Empty(t, keys)

}

// TestRSA2048 ensures an RSA 2048-bit key can be loaded
func TestRSA2048(t *testing.T) {
	authorized_keys := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzgHy8LvI3mUIhplH7aTjtXHE+0CwYtRJS3+LnZfcxUb4z05wUvHhHbt14iNf3vttq0yGDlz0Pfo1uVF84SWeyT4sr/bTNI2S1Ii/Se0FRP4CMfgCuq1+znzRny5SvjWUnHMiI+rmfG6jJX+72QDteRR/AqOdE+qKRN6nXZS1gaZ6dtNnuw4ERWI2Lfgi870K5wCYjsf+Hq9DoDxwBbtzyWIeredPZvmBUlc8z54YcZFx3OVcyOwM1OF+2UpLve9sNoNyQvL9cBS+sQQ2yKEqDCtECM5q0kS2l6mdCouCnJSEdzqXvHxYWEycEVDwgujpPOQrxPkXGMjdyD82ABWIn rsa-2048@test.local"
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, authorized_keys, keys[0].String())

}

// TestRSA4096 ensures an RSA 4096-bit key can be loaded
func TestRSA4096(t *testing.T) {
	authorized_keys := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDVMb0WP8ENdQPyFjwZGSmBBzfF2LS8JQMCBZs1dhhnSsTMac+De7r9V2BMqDIHaW5S7eCSwg5tczebCDQJ0FQMBSkCl6AmIXpews6UI3WHonb5UmVtXJqv7KbjKQW0AcSVkVpzLRMQH2flwONmkZ7CQ9UK2ofi5ctka/ywwMz8I4TmQLIG5P9AVX/CtSLl6b2BMcfSaTmKnc33TtBavZ1bvniJA/AG9xtCmy1RSenO4eqWzlUcriJV3UymPMg3WR/VLRZGDpnnsZdCVbbY6AIyfo3ytS4gY+Ar01oPT9KqwoVutyZebjZHZ5U/ov4fmT1sWf/dGRIc3/fBqpSgMJmbEO9AihArYnkgbB4GMF6VLo1XpCkEhfnOMDAYEC7HP18y7XF4oAIPJPZgnd64QYaW7j7kdDtRTQtG9/z4t8a7qOCwA71288JQRTvIi6fYTIkT6kDwO0GDTsNLu/f/6cvl2hrphDrjSuYUwktZksoaoYk9AO96F5gvhxAsjCqoVz7xhUBzGdYz2D9fEiX09i8KlBJlesrCERoVM0Z1TCCAZ1XBMhss7OFu5mKdEH9zYUy1dT16YcvbLWZD4xzeVNre8EHBt0RlWkWhwSQfwAbRLn4ZsprkuZtRc/L4wr0taO82Oc4IkeyZNJybVh9IM7h3U0VBUrkYQirpHZ2v2SDjiQ== rsa-4096@test.local"
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, authorized_keys, keys[0].String())
}

// TestEd25519 ensures an Edwards curve key can be loaded
func TestEd25519(t *testing.T) {
	authorized_keys := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAqjXHmwbCS1JFjjqZbV9R/DwH3e9lvtqLuY8xUihXzy ed25519@test.local"
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, authorized_keys, keys[0].String())
}

// TestECDSA256 ensures an ECDSA 256-bit key can be loaded
func TestECDSA256(t *testing.T) {
	authorized_keys := "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHQQYhGE5khuF7zOzvT9i0c7GjYIRSBIzMoPxCVnnizlZqAnDUckl+bbKiMwey0+WQ19BbNWoQmIpa7Fr76QazU= ecdsa-256@test.local"
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, authorized_keys, keys[0].String())
}

// TestECDSA384 ensures an ECDSA 384-bit key can be loaded
func TestECDSA384(t *testing.T) {
	authorized_keys := "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBDML4c0mMAyK7PoBYjoZY8ZmmwJLLVkxOsuBEcwcxBNnHgBB1sEsCqHLmwbiAZH6iuMZmILVDgGZW9GqyqMUfyuGRo/iKw2q6jwapI1gbjirGWA43Qmm0n1p8MJUwYzi1Q== ecdsa-384@test.local"
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, authorized_keys, keys[0].String())
}

// TestECDSA521 ensures an ECDSA 521-bit key can be loaded
func TestECDSA521(t *testing.T) {
	authorized_keys := "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHEzIEBuuH1tRTmkm0YLrhf6YcADsnU0ps89DTzdl9i+irxB2zxCQ/C9ZSQRSG4qR3O7JzmspQX4BNAgpSPN1ABFgA9nM2F+ekB5j380l1QQWtqNyTDV+IGXEW9YJW+UpvBG+jjwGfVmcRU1Sr5BQnQ1VQjkNDPEGo23/I8rFyuVOqn+A== ecdsa-521@test.local"
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, authorized_keys, keys[0].String())
}

// TestMultiKey ensures multiple keys from one authorized_keys file can be loaded
func TestMultiKey(t *testing.T) {
	keyA := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKbSCOoPbjJyLjXK+HomCl6SWaagF+YLgP9ctaulAm+Q keyA@test.local"
	keyB := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFFypewABfePuH+hFQpPWlmm5kqjJhMAw9o4s9t2rWAN keyB@test.local"
	keyC := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL83Nr6q4Fd5upaQ8bqFqKGKwZVbmHT1glrvB/8RhwU5 keyC@test.local"
	keyD := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKvpooC3obku1Q9ika1exRJE4pvHVMuWyLhr/ybJHFlB keyD@test.local"
	keyE := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIZk91rDH05SwNBHKA7qh4ct9IyOpG4BYP5YkEQfwA7f keyE@test.local"
	authorized_keys := strings.Join([]string{keyA, keyB, keyC, keyD, keyE}, "\n")

	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	require.Len(t, keys, 5)
	assert.Equal(t, keyA, keys[0].String())
	assert.Equal(t, keyB, keys[1].String())
	assert.Equal(t, keyC, keys[2].String())
	assert.Equal(t, keyD, keys[3].String())
	assert.Equal(t, keyE, keys[4].String())
}

// TestEmptyComment tests loading an authorized_keys entry with an empty comment fails
func TestEmptyComment(t *testing.T) {
	authorized_keys := "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHEzIEBuuH1tRTmkm0YLrhf6YcADsnU0ps89DTzdl9i+irxB2zxCQ/C9ZSQRSG4qR3O7JzmspQX4BNAgpSPN1ABFgA9nM2F+ekB5j380l1QQWtqNyTDV+IGXEW9YJW+UpvBG+jjwGfVmcRU1Sr5BQnQ1VQjkNDPEGo23/I8rFyuVOqn+A=="
	keys, err := parseAuthorizedKeys([]byte(authorized_keys))
	require.NoError(t, err)
	assert.Empty(t, keys)
}
