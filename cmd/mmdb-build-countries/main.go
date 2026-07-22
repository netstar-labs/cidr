// Command mmdb-build-countries builds the cmd/mmdb-write/data/countries.json
// nomenclature file from Wikidata.
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
package main

import (
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

// Some territories are not assigned to a continent in Wikidata,
// so we provide a fallback mapping.
var continentFallback = map[string]string{
	"AX": "EU", // Åland Islands
	"CC": "OC", // Cocos (Keeling) Islands
	"CX": "OC", // Christmas Island
	"GS": "AN", // South Georgia and the South Sandwich Islands
	"IO": "AS", // British Indian Ocean Territory
	"TF": "AN", // French Southern and Antarctic Lands
}

// continentOverride pins a single continent for transcontinental countries —
// whose Wikidata records list two continents — so regeneration is reproducible
// instead of depending on map iteration order. Values match the shipped
// countries.json.
var continentOverride = map[string]string{
	"RU": "EU", // Russia
	"TR": "AS", // Turkey
	"KZ": "EU", // Kazakhstan
	"AZ": "AS", // Azerbaijan
	"GE": "EU", // Georgia
	"AM": "AS", // Armenia
	"CY": "EU", // Cyprus
	"EG": "AF", // Egypt
}

var localePriority = map[string][]string{
	"de":    {"nameDe"},
	"en":    {"nameEn"},
	"es":    {"nameEs"},
	"fr":    {"nameFr"},
	"ja":    {"nameJa"},
	"pt-BR": {"namePtBr", "namePt"},
	"ru":    {"nameRu"},
	"zh-CN": {"nameZh", "nameZhHans"},
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

type wdBinding struct {
	Value string `json:"value"`
}

type wdResult struct {
	Results struct {
		Bindings []map[string]wdBinding `json:"bindings"`
	} `json:"results"`
}

func fetchWikidata(endpoint, query string) (wdResult, error) {
	var result wdResult
	baseURL := endpoint + "?format=json&query=" + url.QueryEscape(query)

	body, err := fetch(baseURL)
	if err != nil {
		return result, err
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return result, fmt.Errorf("decoding Wikidata response: %w", err)
	}
	return result, nil
}

func fetchCountryData(endpoint string) (map[string]countryInfo, error) {
	query := `SELECT ?isoCode ?continentCode ?geonameId ?isEu ?nameDe ?nameEn ?nameEs ?nameFr ?nameJa ?namePtBr ?namePt ?nameRu ?nameZhHans ?nameZh WHERE {
  ?country wdt:P297 ?isoCode.
  FILTER NOT EXISTS { ?country wdt:P31 wd:Q3024240. }
  FILTER NOT EXISTS { ?country wdt:P576 ?end. FILTER(?end < NOW()) }
  FILTER NOT EXISTS { ?country wdt:P582 ?end. FILTER(?end < NOW()) }
  OPTIONAL { ?country wdt:P1566 ?geonameId. }
  OPTIONAL {
    ?country wdt:P30 ?continent.
    VALUES (?continent ?continentCode) {
      (wd:Q15 "AF") (wd:Q51 "AN") (wd:Q48 "AS")
      (wd:Q46 "EU") (wd:Q49 "NA") (wd:Q538 "OC") (wd:Q55643 "OC") (wd:Q18 "SA")
    }
  }
  OPTIONAL {
    ?country (p:P463|(wdt:P150/p:P463)) ?stmt.
    ?stmt ps:P463 wd:Q458.
    FILTER NOT EXISTS { ?stmt pq:P582 ?end. FILTER(?end <= NOW()) }
  }
  BIND(BOUND(?stmt) AS ?isEu)
  OPTIONAL { ?country rdfs:label ?nameDe. FILTER(LANG(?nameDe) = "de") }
  OPTIONAL { ?country rdfs:label ?nameEn. FILTER(LANG(?nameEn) = "en") }
  OPTIONAL { ?country rdfs:label ?nameEs. FILTER(LANG(?nameEs) = "es") }
  OPTIONAL { ?country rdfs:label ?nameFr. FILTER(LANG(?nameFr) = "fr") }
  OPTIONAL { ?country rdfs:label ?nameJa. FILTER(LANG(?nameJa) = "ja") }
  OPTIONAL { ?country rdfs:label ?namePtBr. FILTER(LANG(?namePtBr) = "pt-br") }
  OPTIONAL { ?country rdfs:label ?namePt. FILTER(LANG(?namePt) = "pt") }
  OPTIONAL { ?country rdfs:label ?nameRu. FILTER(LANG(?nameRu) = "ru") }
  OPTIONAL { ?country rdfs:label ?nameZhHans. FILTER(LANG(?nameZhHans) = "zh-hans") }
  OPTIONAL { ?country rdfs:label ?nameZh. FILTER(LANG(?nameZh) = "zh-cn") }
}`

	result, err := fetchWikidata(endpoint, query)
	if err != nil {
		return nil, err
	}

	type acc struct {
		geonameID  uint
		names      map[string]string
		eu         bool
		continents map[string]bool
	}

	accs := make(map[string]*acc)

	for _, b := range result.Results.Bindings {
		iso := strings.TrimSpace(b["isoCode"].Value)
		if iso == "" {
			continue
		}

		a, ok := accs[iso]
		if !ok {
			a = &acc{
				names:      make(map[string]string),
				continents: make(map[string]bool),
			}
			accs[iso] = a
		}

		if gidStr, ok := b["geonameId"]; ok && a.geonameID == 0 {
			gid, err := strconv.ParseUint(strings.TrimSpace(gidStr.Value), 10, 64)
			if err == nil {
				a.geonameID = uint(gid)
			}
		}

		if cc, ok := b["continentCode"]; ok {
			a.continents[strings.TrimSpace(cc.Value)] = true
		}

		if isEU, ok := b["isEu"]; ok && isEU.Value == "true" {
			a.eu = true
		}

		for locale, keys := range localePriority {
			if _, exists := a.names[locale]; exists {
				continue
			}
			for _, wdKey := range keys {
				if val, ok := b[wdKey]; ok {
					name := strings.TrimSpace(val.Value)
					if name != "" {
						a.names[locale] = name
						break
					}
				}
			}
		}
	}

	if len(accs) == 0 {
		return nil, fmt.Errorf("no country records found from Wikidata")
	}

	countries := make(map[string]countryInfo, len(accs))
	for iso, a := range accs {
		ci := countryInfo{
			GeonameID:         a.geonameID,
			Names:             a.names,
			IsInEuropeanUnion: a.eu,
		}

		if ov, ok := continentOverride[iso]; ok {
			ci.ContinentCode = ov // transcontinental: pin the canonical continent
		} else if len(a.continents) > 0 {
			ci.ContinentCode = pickContinent(a.continents)
		} else if fb, ok := continentFallback[iso]; ok {
			ci.ContinentCode = fb
		}

		countries[iso] = ci
	}

	return countries, nil
}

func fetchContinentData(endpoint string) (map[string]continentInfo, error) {
	query := `SELECT ?continentCode ?geonameId ?nameDe ?nameEn ?nameEs ?nameFr ?nameJa ?namePtBr ?namePt ?nameRu ?nameZhHans ?nameZh WHERE {
  VALUES (?continent ?continentCode) {
    (wd:Q15 "AF") (wd:Q51 "AN") (wd:Q48 "AS")
    (wd:Q46 "EU") (wd:Q49 "NA") (wd:Q55643 "OC") (wd:Q18 "SA")
  }
  OPTIONAL { ?continent wdt:P1566 ?geonameId. }
  OPTIONAL { ?continent rdfs:label ?nameDe. FILTER(LANG(?nameDe) = "de") }
  OPTIONAL { ?continent rdfs:label ?nameEn. FILTER(LANG(?nameEn) = "en") }
  OPTIONAL { ?continent rdfs:label ?nameEs. FILTER(LANG(?nameEs) = "es") }
  OPTIONAL { ?continent rdfs:label ?nameFr. FILTER(LANG(?nameFr) = "fr") }
  OPTIONAL { ?continent rdfs:label ?nameJa. FILTER(LANG(?nameJa) = "ja") }
  OPTIONAL { ?continent rdfs:label ?namePtBr. FILTER(LANG(?namePtBr) = "pt-br") }
  OPTIONAL { ?continent rdfs:label ?namePt. FILTER(LANG(?namePt) = "pt") }
  OPTIONAL { ?continent rdfs:label ?nameRu. FILTER(LANG(?nameRu) = "ru") }
  OPTIONAL { ?continent rdfs:label ?nameZhHans. FILTER(LANG(?nameZhHans) = "zh-hans") }
  OPTIONAL { ?continent rdfs:label ?nameZh. FILTER(LANG(?nameZh) = "zh-cn") }
}`

	result, err := fetchWikidata(endpoint, query)
	if err != nil {
		return nil, err
	}

	continents := make(map[string]continentInfo)
	for _, b := range result.Results.Bindings {
		code := ""
		if c, ok := b["continentCode"]; ok {
			code = strings.TrimSpace(c.Value)
		}
		if code == "" {
			continue
		}

		ci := continents[code]

		if gidStr, ok := b["geonameId"]; ok && ci.GeonameID == 0 {
			gid, err := strconv.ParseUint(strings.TrimSpace(gidStr.Value), 10, 64)
			if err == nil {
				ci.GeonameID = uint(gid)
			}
		}

		if ci.Names == nil {
			ci.Names = make(map[string]string)
		}

		for locale, keys := range localePriority {
			if _, exists := ci.Names[locale]; exists {
				continue
			}
			for _, wdKey := range keys {
				if val, ok := b[wdKey]; ok {
					name := strings.TrimSpace(val.Value)
					if name != "" {
						ci.Names[locale] = name
						break
					}
				}
			}
		}
		continents[code] = ci
	}

	return continents, nil
}

// pickContinent returns one continent code deterministically. A multi-continent
// country not covered by continentOverride lands here; sorting makes the choice
// reproducible across runs (map iteration order is not).
func pickContinent(conts map[string]bool) string {
	codes := make([]string, 0, len(conts))
	for c := range conts {
		codes = append(codes, c)
	}
	if len(codes) == 0 {
		return ""
	}
	sort.Strings(codes)
	return codes[0]
}

func main() {
	version := flag.Bool("version", false, "print version and exit")
	wdEndpoint := flag.String("wikidata-url", "https://query.wikidata.org/sparql", "Wikidata SPARQL endpoint URL")
	out := flag.String("o", "cmd/mmdb-write/data/countries.json", "output JSON")
	flag.Parse()

	if *version {
		fmt.Printf("mmdb-build-countries %s (%s)\n", Version, Revision)
		return
	}

	countries, err := fetchCountryData(*wdEndpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	continents, err := fetchContinentData(*wdEndpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

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
