// Package-local paging helper (D813).
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// maxListPages bounds the follow loop. A provider that keeps handing back the same token
// would otherwise spin forever, and a discovery sweep is supposed to be gentle (D141).
// The bound is loud when reached: the caller gets an error rather than a short list that
// looks complete.
const maxListPages = 50

// listAllPages GETs listURL and follows nextPageToken, handing each page's raw body to
// collect. It exists because every Google API pages the same way and the drivers were
// each reading the first page only (D803 made that visible; this makes it untrue).
//
// The caller decodes: the shapes differ per API, and a helper that decoded for them would
// have to know all of them. What is shared is the LOOP, and the loop is where the bug was.
func (d *Driver) listAllPages(op, listURL string, collect func(body []byte) error) error {
	token := ""
	for page := 0; ; page++ {
		if page >= maxListPages {
			return fmt.Errorf("%s: still paging after %d requests — refusing to keep "+
				"going, and refusing to report the pages read so far as the whole list",
				op, maxListPages)
		}
		u := listURL
		if token != "" {
			sep := "?"
			if strings.Contains(u, "?") {
				sep = "&"
			}
			u += sep + "pageToken=" + url.QueryEscape(token)
		}
		st, body, err := d.call("GET", u, nil)
		if err != nil {
			return readTransport(op, err)
		}
		if st != http.StatusOK {
			return readHTTP(op, st, gcpErrCode(body))
		}
		if err := collect(body); err != nil {
			return err
		}
		var envelope struct {
			NextPageToken string `json:"nextPageToken"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return readBody(op, st)
		}
		if envelope.NextPageToken == "" {
			return nil
		}
		token = envelope.NextPageToken
	}
}
