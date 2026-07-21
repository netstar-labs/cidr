// Command mmdb-build-countries builds the cmd/mmdb-write/data/countries.json
// nomenclature file from geonames.org data, enriched with EU membership from Wikidata.
// It extracts a list of countries from geonames.org
// (https://download.geonames.org/export/dump/countryInfo.txt)
// enriches it with alternate names in each language
// (https://download.geonames.org/export/dump/alternateNamesV2.zip)
// and adds a boolean field for EU membership from Wikidata.
// The output is a JSON file with the following structure:
//
//	{
//	  "continents": {
//	    "AF": {"geoname_id": 6255146, "names": {"en": "Africa", "de": "Afrika", ...}},
//	    ...
//	  },
//	  "countries": {
//	    "US": {"geoname_id": 6252001, "names": {"en": "United States"...}, "continent_code": "NA", "is_in_european_union": false},
//	    ...
//	  }
//	}
//
// The output file can be used by the mmdb-write command to generate a MaxMind DB file.
//
// The command can be run as follows:
// `mmdb-build-countries -o cmd/mmdb-write/data/countries.json`
//
// The command can be run with the -skip-alt flag to skip downloading and processing alternate names,
// and with the -skip-eu flag to skip querying Wikidata for EU membership.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Version and Revision are stamped at build time via -ldflags -X.
var (
	Version  = "dev"
	Revision = "unknown"
)

type continentInfo struct {
	GeonameID uint              `json:"geoname_id"`
	Names     map[string]string `json:"names"`
}

type countryInfo struct {
	GeonameID         uint              `json:"geoname_id"`
	Names             map[string]string `json:"names"`
	ContinentCode     string            `json:"continent_code"`
	IsInEuropeanUnion bool              `json:"is_in_european_union"`
}

type output struct {
	Continents map[string]continentInfo `json:"continents"`
	Countries  map[string]countryInfo   `json:"countries"`
}

// Taken from https://download.geonames.org/export/dump/readme.txt
// This list of continents is not going to change in the next few centuries
var builtinContinents = map[string]continentInfo{
	"AF": {GeonameID: 6255146, Names: map[string]string{"en": "Africa"}},
	"AN": {GeonameID: 6255152, Names: map[string]string{"en": "Antarctica"}},
	"AS": {GeonameID: 6255147, Names: map[string]string{"en": "Asia"}},
	"EU": {GeonameID: 6255148, Names: map[string]string{"en": "Europe"}},
	"NA": {GeonameID: 6255149, Names: map[string]string{"en": "North America"}},
	"OC": {GeonameID: 6255151, Names: map[string]string{"en": "Oceania"}},
	"SA": {GeonameID: 6255150, Names: map[string]string{"en": "South America"}},
}

func fetch(url string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "fetching %s ...\n", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mmdb-build-countries/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	return body, nil
}

func parseCountryInfo(body []byte) (map[string]countryInfo, map[string]continentInfo, error) {
	continents := make(map[string]continentInfo)
	for k, v := range builtinContinents {
		continents[k] = v
	}

	countries := make(map[string]countryInfo)

	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "")
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 17 {
			continue
		}
		isoCode := strings.TrimSpace(fields[0])
		countryName := strings.TrimSpace(fields[4])
		continentCode := strings.TrimSpace(fields[8])
		geonameIDStr := strings.TrimSpace(fields[16])
		if isoCode == "" || countryName == "" || continentCode == "" {
			continue
		}
		geonameID, _ := strconv.ParseUint(geonameIDStr, 10, 64)
		if _, exists := countries[isoCode]; !exists {
			countries[isoCode] = countryInfo{
				GeonameID:         uint(geonameID),
				Names:             map[string]string{"en": countryName},
				ContinentCode:     continentCode,
				IsInEuropeanUnion: false,
			}
		}
	}
	if len(countries) == 0 {
		return nil, nil, fmt.Errorf("no country records found in countryInfo.txt")
	}
	return countries, continents, nil
}

func processAlternateNames(body []byte, countries map[string]countryInfo, continents map[string]continentInfo) error {
	// Build the alternate country names list
	fmt.Fprintf(os.Stderr, "unzipping alternateNamesV2.txt ...\n")
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}

	var f *zip.File
	for _, zf := range zipReader.File {
		if zf.Name == "alternateNamesV2.txt" {
			f = zf
			break
		}
	}
	if f == nil {
		return fmt.Errorf("alternateNamesV2.txt not found in zip")
	}

	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("opening alternateNamesV2.txt: %w", err)
	}
	defer rc.Close()

	geonameIDToISO := make(map[uint]string, len(countries))
	for iso, ci := range countries {
		geonameIDToISO[ci.GeonameID] = iso
	}

	geonameIDToContinent := make(map[uint]string, len(continents))
	for code, ci := range continents {
		geonameIDToContinent[ci.GeonameID] = code
	}

	// Only languages that are included in the MaxMind DBs are included
	allowed := map[string]string{
		"de": "de", "en": "en", "es": "es", "fr": "fr",
		"ja": "ja", "pt": "pt-BR", "ru": "ru", "zh": "zh-CN",
	}

	fmt.Fprintf(os.Stderr, "parsing alternate names ...\n")
	scanner := bufio.NewScanner(rc)
	buf := make([]byte, 1<<20)
	scanner.Buffer(buf, 1<<20)

	var lineNum int64
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}

		gid64, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 64)
		if err != nil {
			continue
		}
		gid := uint(gid64)

		lang := strings.TrimSpace(fields[2])
		name := strings.TrimSpace(fields[3])
		if lang == "" || name == "" {
			continue
		}
		outLang, ok := allowed[lang]
		if !ok {
			continue
		}

		preferred := len(fields) > 4 && strings.TrimSpace(fields[4]) == "1"

		if iso, ok := geonameIDToISO[gid]; ok {
			if outLang != "en" {
				ci := countries[iso]
				if _, exists := ci.Names[outLang]; !exists || preferred {
					ci.Names[outLang] = name
					countries[iso] = ci
				}
			}
		}

		if code, ok := geonameIDToContinent[gid]; ok {
			if outLang != "en" {
				ci := continents[code]
				if _, exists := ci.Names[outLang]; !exists || preferred {
					ci.Names[outLang] = name
					continents[code] = ci
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanning alternate names at line %d: %w", lineNum, err)
	}
	return nil
}

// Wikidata's SparQL endpoint returns a JSON object with the following structure
type sparqlBinding struct {
	Iso2 struct {
		Value string `json:"value"`
	} `json:"iso2"`
	End *struct {
		Value string `json:"value"`
	} `json:"end,omitempty"`
}

type sparqlResult struct {
	Results struct {
		Bindings []sparqlBinding `json:"bindings"`
	} `json:"results"`
}

func fetchEUcodes() (map[string]bool, error) {
	fmt.Fprintf(os.Stderr, "fetching EU member codes from Wikidata ...\n")

	query := `SELECT ?isoCode WHERE {
  ?country p:P463 ?membership; p:P297 ?isoStatement.
  ?membership ps:P463 wd:Q458.
  ?isoStatement ps:P297 ?isoCode.
  FILTER NOT EXISTS {
    ?membership pq:P582 ?endDate.
    FILTER(?endDate <= NOW())
  }
}`
	baseURL := "https://query.wikidata.org/sparql?format=json&query=" + url.QueryEscape(query)

	body, err := fetch(baseURL)
	if err != nil {
		return nil, err
	}

	var sr struct {
		Results struct {
			Bindings []struct {
				IsoCode struct {
					Value string `json:"value"`
				} `json:"isoCode"`
			} `json:"bindings"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("decoding Wikidata response: %w", err)
	}

	eu := make(map[string]bool)
	for _, b := range sr.Results.Bindings {
		eu[b.IsoCode.Value] = true
	}
	return eu, nil
}

func main() {
	version := flag.Bool("version", false, "print version and exit")
	countryURL := flag.String("country-url", "https://download.geonames.org/export/dump/countryInfo.txt", "geonames countryInfo.txt URL")
	altURL := flag.String("alt-url", "https://download.geonames.org/export/dump/alternateNamesV2.zip", "geonames alternateNamesV2.zip URL")
	out := flag.String("o", "cmd/mmdb-write/data/countries.json", "output JSON")
	skipAlt := flag.Bool("skip-alt", false, "skip alternate names download")
	skipEU := flag.Bool("skip-eu", false, "skip Wikidata EU member query")
	flag.Parse()

	if *version {
		fmt.Printf("mmdb-build-countries %s (%s)\n", Version, Revision)
		return
	}

	body, err := fetch(*countryURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// First: download country data from countryInfo.txt (geonames.org)
	countries, continents, err := parseCountryInfo(body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if !*skipAlt {
		// Second: download alternate names from alternateNamesV2.zip (geonames.org)
		// These are the translations of the country names in various languages
		altBody, err := fetch(*altURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if err := processAlternateNames(altBody, countries, continents); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	}

	if !*skipEU {
		// Third: query Wikidata for EU membership and mark the countries accordingly
		euCodes, err := fetchEUcodes()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to fetch EU codes: %v\n", err)
		} else {
			for iso := range countries {
				if euCodes[iso] {
					ci := countries[iso]
					ci.IsInEuropeanUnion = true
					countries[iso] = ci
				}
			}
		}
	}

	// Finally: write the output JSON file with the continents and countries
	// This will be used by the mmdb-write command to generate a MaxMind DB file (Country)
	sorted := output{
		Continents: make(map[string]continentInfo, len(continents)),
		Countries:  make(map[string]countryInfo, len(countries)),
	}
	for _, code := range sortedKeys(continents) {
		sorted.Continents[code] = continents[code]
	}
	for _, code := range sortedKeys(countries) {
		sorted.Countries[code] = countries[code]
	}

	data, err := json.MarshalIndent(sorted, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*out, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *out, err)
		os.Exit(1)
	}

	fmt.Printf("%d continents, %d countries -> %s\n",
		len(continents), len(countries), *out)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
