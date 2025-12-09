package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	_ "github.com/go-sql-driver/mysql"
	"github.com/xwb1989/sqlparser"
)

var (
	DBWriter *MysqlServer
	DBWrite  *sql.DB
	Token    string   = "ee776f0d5ddce1f4acd1b99fce959e185c032a9e"
	YSFUrl   string   = "https://dvref.com/ysf/reflectors/?include_description=true"
	NXDNUrl  string   = "https://dvref.com/nxdn/reflectors/?include_description=true"
	URFUrl   string   = "https://dvref.com/urfd/reflectors/?include_description=true&mode=%s&resolve_ips=true"
	URFModes []string = []string{"DMR", "P25", "NXDN", "YSF", "REF", "XRF", "DCS", "M17"}
)

type MysqlServer struct {
	Hostname string
	Dbname   string
	Dbuser   string
	Dbpass   string
}

func NewMysqLServer() *MysqlServer {
	return &MysqlServer{
		Hostname: "localhost",
		Dbname:   "hamradio",
		Dbuser:   "admin",
		Dbpass:   "nskdm1153",
	}
}

type Result struct {
	Status      string           `json:"status"`       // "success",
	GeneratedAt string           `json:"generated_at"` // "2025-04-24T12:32:38.930137",
	Reflectors  []map[string]any `json:"reflectors"`
}

type YSFReflector struct {
	Designator           string `json:"designator"`           // "00007",
	Name                 string `json:"name"`                 // "cumbriaCQ.com",
	Use_xx_prefix        bool   `json:"use_xx_prefix"`        // false,
	Description          string `json:"description"`          // "cumbriaCQ.com",
	Slug                 string `json:"slug"`                 // "ysf-00007-cumbriacqcom",
	Url                  string `json:"url"`                  // "https://urf001.cumbriacq.com/urf/",
	Dns                  string `json:"dns"`                  // "digital.cumbriacq.com",
	Ipv4                 string `json:"ipv4"`                 // null,
	Ipv6                 string `json:"ipv6"`                 // null,
	Port                 int32  `json:"port"`                 // 42100,
	Sponsor              string `json:"sponsor"`              // "cumbriaCQ.com",
	Country              string `json:"country"`              // "GB"
	User_count           string `json:"user_count"`           // "000",
	Ip_source            string `json:"ip_source"`            // "dns",
	Dns_cache_updated_at string `json:"dns_cache_updated_at"` // "2025-06-25T15:16:12.427688Z",
	Last_verified_at     string `json:"last_verified_at"`     // "2025-06-02T15:10:57.043817Z",
	Extended_description string `json:"extended_description"` // "<p>Bridge: BM - TG 20208&nbsp; and IPS2- Sweden TG 20269&nbsp;</p>\r\n<p>&nbsp;</p>"
}

type NXDNReflector struct {
	Designator           int32  `json:"designator"`           // 11,
	Name                 string `json:"name"`                 // null,
	Slug                 string `json:"slug"`                 // "nxdn-11",
	Url                  string `json:"url"`                  // "https://hellaszone.com/index.php/nxdn-server",
	Dns                  string `json:"dns"`                  // "cqzone.org",
	Ipv4                 string `json:"ipv4"`                 // "46.59.68.211",
	Ipv6                 string `json:"ipv6"`                 // null,
	Port                 int32  `json:"port"`                 // 41401,
	Sponsor              string `json:"sponsor"`              // "HELLAS Zone Net! SA7SVR",
	Country              string `json:"country"`              // "GR",
	Ip_source            string `json:"ip_source"`            // "dns",
	Dns_cache_updated_at string `json:"dns_cache_updated_at"` // "2025-07-20T13:16:18.545740Z",
	Last_verified_at     string `json:"last_verified_at"`     // "2025-04-23T15:21:03.105350Z",
	Description          string `json:"description"`          // ""
}

type URFModule struct {
	Designator  string `json:"designator"`  // "",
	Module      string `json:"module"`      // "C",
	Slug        string `json:"slug"`        // "033-module-c",
	Mode        string `json:"mode"`        // "All",
	Description string `json:"description"` // "France D-Star",
	Transcode   bool   `json:"transcode"`   // true
}

type URFReflector struct {
	Designator           string      `json:"designator"` // "033",
	Name                 string      `json:"name"`       // "XLX033",
	Slug                 string      `json:"slug"`       // "urf033",
	Url                  string      `json:"url"`        // "http://dcs033.xreflector.net",
	Dns                  string      `json:"dns"`        // null,
	Ipv4                 string      `json:"ipv4"`       // "164.132.230.151",
	Ipv6                 string      `json:"ipv6"`       // null,
	Sponsor              string      `json:"sponsor"`    // "F4GEN",
	Country              string      `json:"country"`    // "FR",
	EnabledModes         []string    `json:"enable_modes"`
	Modules              []URFModule `json:"modules"`
	Ip_source            string      `json:"ip_source"`            // "static",
	Dns_cache_updated_at string      `json:"dns_cache_updated_at"` // null,
	Description          string      `json:"description"`          // ""
}

func (srv *MysqlServer) DbConnect(conns int) (*sql.DB, error) {
	var err error

	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?multiStatements=true&parseTime=true", srv.Dbuser, srv.Dbpass, srv.Hostname, srv.Dbname)

	var dbConn *sql.DB
	for i := 0; i < 10; i++ {
		dbConn, err = sql.Open("mysql", dsn)
		if err == nil {
			break
		}

		time.Sleep(time.Duration(i) * 200 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}

	dbConn.SetConnMaxLifetime(1 * time.Minute)
	dbConn.SetMaxIdleConns(conns)
	dbConn.SetMaxOpenConns(conns)

	err = dbConn.Ping()
	if err != nil {
		return nil, err
	}

	return dbConn, nil
}

func MysqlRealEscapeString(value string) string {
	var sb strings.Builder
	for i := range len(value) {
		c := value[i]
		switch c {
		case '\\', 0, '\n', '\r', '\'', '"':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case '\032':
			sb.WriteByte('\\')
			sb.WriteByte('Z')
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func IsSQLValid(sql string) (bool, error) {
	var syntaxCheck []string = []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE "}

	if slices.Contains(syntaxCheck, strings.ToUpper(string(sql[0:7]))) {
		if _, err := sqlparser.Parse(sql); err != nil {
			return false, err
		}
	}
	return true, nil
}

func AddslashesGo(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\") // Escape backslashes first
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\x00", "\\0") // NULL character
	return s
}

func StripHtmlTags(s string) string {
	const (
		htmlTagStart = 60 // Unicode `<`
		htmlTagEnd   = 62 // Unicode `>`
	)

	var builder strings.Builder
	builder.Grow(len(s) + utf8.UTFMax)

	in := false
	start := 0
	end := 0

	for i, c := range s {
		if (i+1) == len(s) && end >= start {
			builder.WriteString(s[end:])
		}
		if c != htmlTagStart && c != htmlTagEnd {
			continue
		}
		if c == htmlTagStart {
			if !in {
				start = i
				builder.WriteString(s[end:start])
			}
			in = true
			continue
		}
		// else c == htmlTagEnd
		in = false
		end = i + 1
	}
	s = builder.String()
	return s
}

func CleanSQLString(input string) string {
	// This regex matches any character that is NOT a printable ASCII character
	// (space to tilde, inclusive). This excludes extended characters and control characters.
	reg := regexp.MustCompile(`[^\x20-\x7E]`)
	cleaned := reg.ReplaceAllString(input, "")
	return cleaned
}

// Control deadlock para todos los exec
// https://medium.com/nerd-for-tech/db-dead-lock-complete-case-study-using-golang-15dd754e5cb8
func ExecTransaction(query string, timeoutsec time.Duration) (res sql.Result, err error) {
	var tx *sql.Tx

	if ok, errSqsl := IsSQLValid(query); !ok && errSqsl != nil {
		err = fmt.Errorf("invalid sql %s : %s", query, errSqsl.Error())
		return nil, err
	}

	var errExec error

	query = CleanSQLString(query)

	ctx, cancel := context.WithTimeout(context.Background(), timeoutsec*time.Second)
	defer func() {
		if tx != nil {
			if errExec == nil {
				tx.Commit()
			} else {
				tx.Rollback()
			}
		}
		cancel()
	}()

	timeInc := 0
	for range 10 {
		if tx, err = DBWrite.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelDefault}); err == nil {
			if res, errExec = tx.ExecContext(ctx, query); errExec == nil {
				tx.Commit()
				break
			}
		}
		if errExec != nil && (strings.Contains(strings.ToLower(errExec.Error()), "is not registered") ||
			strings.Contains(strings.ToLower(errExec.Error()), "doesn't exist") ||
			strings.Contains(strings.ToLower(errExec.Error()), "error in your sql syntax") ||
			strings.Contains(strings.ToLower(errExec.Error()), "cannot add or update a child") ||
			strings.Contains(strings.ToLower(errExec.Error()), "unknown column")) {
			break
		}
		if tx != nil {
			tx.Rollback()
		}
		time.Sleep(time.Duration(timeInc) * 200 * time.Millisecond)
		timeInc++
	}

	if errExec != nil {
		return res, fmt.Errorf("error %s exec %s", errExec, query)
	}
	return res, err
}

// contruir la parte de update o insert segun estructura o map
func QBuild(data any, qtype string, excludes []string) string {
	var record map[string]interface{}
	jsonStr, _ := json.Marshal(data)
	json.Unmarshal(jsonStr, &record)

	fields := make([]string, 0)
	values := make([]string, 0)

	excludes = append(excludes, "created_at")
	excludes = append(excludes, "updated_at")
	excludes = append(excludes, "deleted_at")

	for f, value := range record {
		if slices.Contains(excludes, f) {
			continue
		}
		if value != nil {
			rt := reflect.TypeOf(value)
			fields = append(fields, fmt.Sprintf("`%s`", f))
			if rt.Kind() == reflect.String {
				values = append(values, fmt.Sprintf("'%s'", strings.ReplaceAll(value.(string), "'", "\\'")))
			} else {
				values = append(values, fmt.Sprintf("%v", value))
			}
		}
	}

	var result string = ""
	if strings.ToUpper(qtype) == "UPDATE" {
		for i, field := range fields {
			result = fmt.Sprintf("%s%s=%s,", result, field, values[i])
		}
		result = result[:len(result)-1]
	}
	if strings.ToUpper(qtype) == "INSERT" {
		result = fmt.Sprintf("(%s) VALUES (%s)", strings.Join(fields, ","), strings.Join(values, ","))
	}

	return result

}

func PrettyPrint(b []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "  ")
	return out.Bytes(), err
}

func ConvertArrayAnyToString(data []any) (output []string) {
	output = []string{}
	for _, v := range data {
		if s, ok := v.(string); ok {
			output = append(output, s)
		}
	}
	return output
}

func GetReflectors(name string, params ...string) {
	var reflectors *Result
	var err error
	var resp *http.Response
	var body []byte
	var sql, urlSrc string = "", ""
	var urfReflector map[string]any
	var urfModules []any
	var modes []any
	var designator string
	var urfModule URFModule

	DBWriter = NewMysqLServer()
	if DBWrite, err = DBWriter.DbConnect(10); err != nil {
		log.Fatal(err.Error())
	}
	defer DBWrite.Close()

	switch name {
	case "ysf_reflectors":
		urlSrc = YSFUrl
	case "nxdn_reflectors":
		urlSrc = NXDNUrl
	case "urf_reflectors":
		if len(params) <= 0 {
			params = []string{"XRF"}
		}
		urlSrc = fmt.Sprintf(URFUrl, params[0])

	}

	client := http.Client{}
	req, err := http.NewRequest("GET", urlSrc, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header = http.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {fmt.Sprintf("Token %s", Token)},
	}

	resp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(body, &reflectors)
	if err != nil {
		log.Fatal(err)
	}

	for _, reflector := range reflectors.Reflectors {

		if name == "urf_reflectors" {
			urfReflector = reflector

			urfModules = urfReflector["modules"].([]any)
			designator = urfReflector["designator"].(string)
			if _, err = ExecTransaction(fmt.Sprintf("DELETE FROM urf_modules WHERE designator='%s'", designator), 30); err != nil {
				fmt.Println(err.Error())
			}

			for _, module := range urfModules {
				urfModule = URFModule{}
				if jsonBytes, err := json.Marshal(module); err == nil {
					if err = json.Unmarshal(jsonBytes, &urfModule); err == nil {
						urfModule.Designator = designator
						sql = fmt.Sprintf("INSERT INTO urf_modules %s", QBuild(urfModule, "INSERT", nil))
						if _, err = ExecTransaction(sql, 30); err != nil {
							fmt.Println(err.Error())
						}
					} else {
						fmt.Println(err.Error())
					}
				}
			}

			delete(urfReflector, "modules")

			modes = urfReflector["enabled_modes"].([]any)
			delete(urfReflector, "enabled_modes")

			urfReflector["enabled_modes"] = strings.Join(ConvertArrayAnyToString(modes), ",")
			reflector = urfReflector
		}
		sql = fmt.Sprintf("REPLACE INTO %s %s", name, QBuild(reflector, "INSERT", nil))
		if _, err = ExecTransaction(sql, 30); err != nil {
			log.Fatal(sql, err.Error())
			fmt.Println(sql, err.Error())
			break
		}
	}

}

func main() {
	GetReflectors("urf_reflectors")
	GetReflectors("ysf_reflectors")
	GetReflectors("nxdn_reflectors")
}
