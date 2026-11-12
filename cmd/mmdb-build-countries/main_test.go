package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestMissingFields(t *testing.T) {
	continents := map[string]continentInfo{"EU": {GeonameID: 1}}
	countries := map[string]countryInfo{
		"DE": {GeonameID: 2921044, Names: map[string]string{"en": "Germany"}, ContinentCode: "EU"},
		"NL": {Names: map[string]string{"en": "Netherlands"}, ContinentCode: "EU"},
		"AC": {GeonameID: 2411430, Names: map[string]string{"en": "Ascension"}},
		"ZZ": {GeonameID: 1, Names: map[string]string{"de": "x"}, ContinentCode: "QQ"},
	}
	got := missingFields(countries, continents)
	want := []string{
		`AC: continent ("")`,
		"NL: geoname_id",
		`ZZ: continent ("QQ"), en name`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("missingFields = %q, want %q", got, want)
	}
}

// A country without a geoname_id is written without the key, not as 0.
func TestUnknownGeonameIDOmitted(t *testing.T) {
	b, err := json.Marshal(countryInfo{Names: map[string]string{"en": "X"}, ContinentCode: "EU"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "geoname_id") {
		t.Errorf("json = %s, want no geoname_id", b)
	}
}

// TestContinentFallback runs fetchCountryData against a canned Wikidata answer:
// AC, TA and CQ come back with no continent, and take the explicit fallback.
func TestContinentFallback(t *testing.T) {
	const body = `{"results":{"bindings":[
	  {"isoCode":{"value":"AC"},"geonameId":{"value":"2411430"},"nameEn":{"value":"Ascension"}},
	  {"isoCode":{"value":"TA"},"geonameId":{"value":"3370684"},"nameEn":{"value":"Tristan da Cunha"}},
	  {"isoCode":{"value":"CQ"},"geonameId":{"value":"3042282"},"nameEn":{"value":"Sark"}},
	  {"isoCode":{"value":"DE"},"geonameId":{"value":"2921044"},"continentCode":{"value":"EU"},"nameEn":{"value":"Germany"}}
	]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()
	countries, err := fetchCountryData(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for code, want := range map[string]string{"AC": "AF", "TA": "AF", "CQ": "EU", "DE": "EU"} {
		if got := countries[code].ContinentCode; got != want {
			t.Errorf("%s continent = %q, want %q", code, got, want)
		}
	}
}
