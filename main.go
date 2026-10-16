package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID             int
	Username, Role string
}
type Note struct {
	ID, UserID, Replies   int
	Owner, Title, Content string
	Created               time.Time
}
type Comment struct {
	ID                int
	Username, Message string
	Created           time.Time
}
type Session struct {
	User    *User
	CSRF    string
	Expires time.Time
}
type Page struct {
	User     *User
	CSRF     string
	Error    string
	Notes    []Note
	Comments []Comment
	Users    []User
	Note     Note
}

var (
	db       *sql.DB
	sessions = map[string]*Session{}
	mu       sync.Mutex

	// กัน brute force หน้า login
	fails   = map[string]*failInfo{}
	failsMu sync.Mutex

	trustProxy = os.Getenv("TRUST_PROXY") == "1" // ตั้งเป็น 1 เมื่อรันหลัง reverse proxy ของโฮส (Render, Railway ฯลฯ)
	dummyHash  []byte                            // ใช้เทียบรหัสปลอมตอนไม่พบ user กัน timing attack
)

const maxSessions = 50000 // จำกัดจำนวน session ของคนที่ยังไม่ login กัน memory เต็ม

type failInfo struct {
	n     int
	until time.Time
}

// ---------- หน้าเว็บ (HTML template: escape อัตโนมัติ กัน XSS) ----------
const pages = `
{{define "head"}}<!DOCTYPE html><html><head><meta charset="utf-8"><title>Go App</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
*{box-sizing:border-box}
:root{--red:#b83245;--red-d:#8f2436;--red-l:#fbeaec;--line:#f0d5d9;--ink:#2b2224;--mute:#7a6a6d}
body{font-family:'Segoe UI','Noto Sans Thai',Tahoma,sans-serif;background:#faf5f5;color:var(--ink);
  max-width:780px;margin:0 auto;padding:0 16px 48px;line-height:1.6}
hr{display:none}
a{color:var(--red);text-decoration:none}
a:hover{text-decoration:underline}
nav{background:linear-gradient(135deg,#c23b4e,#9b2639);color:#fff;border-radius:0 0 16px 16px;
  margin:0 0 26px;padding:14px 20px;display:flex;flex-wrap:wrap;gap:16px;align-items:center;
  box-shadow:0 4px 14px rgba(155,38,57,.25)}
nav a{color:#fff;font-weight:500}
nav .brand{font-size:1.25em;font-weight:700;letter-spacing:.3px}
nav .sp{flex:1}
nav .who{opacity:.9;font-size:.95em}
nav form.inline{margin:0}
nav button{background:#fff;color:var(--red);font-weight:600;padding:6px 14px}
nav button:hover{background:var(--red-l)}
h2{margin:0 0 18px;font-size:1.5em;color:var(--red-d)}
h3{margin:0 0 12px;color:var(--red-d)}
.box{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:16px 0;
  box-shadow:0 2px 8px rgba(120,40,50,.06)}
.thread,.post{border-left:5px solid var(--red)}
.thread{transition:box-shadow .15s,transform .15s}
.thread:hover{box-shadow:0 8px 20px rgba(120,40,50,.14);transform:translateY(-1px)}
.thread a.title{color:var(--ink);font-size:1.2em;font-weight:700}
.thread a.title:hover{color:var(--red);text-decoration:none}
.meta{color:var(--mute);font-size:.85em;margin:2px 0 8px}
.thread .content{margin:6px 0}
.thread-foot{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-top:12px;padding-top:12px;
  border-top:1px dashed var(--line);font-size:.92em}
.badge{background:var(--red-l);color:var(--red-d);border-radius:999px;padding:2px 12px;font-size:.85em;font-weight:600}
.content{white-space:pre-wrap;word-break:break-word}
input,textarea{display:block;width:100%;margin:8px 0 12px;padding:10px 12px;background:#fffdfd;
  border:1px solid #e3c9cd;border-radius:8px;font:inherit}
input:focus,textarea:focus{outline:none;border-color:var(--red);box-shadow:0 0 0 3px rgba(184,50,69,.15)}
textarea{min-height:100px;resize:vertical}
button{background:var(--red);color:#fff;border:0;border-radius:8px;padding:9px 18px;font:inherit;
  font-weight:600;cursor:pointer;transition:background .15s}
button:hover{background:var(--red-d)}
form[action*=delete] button{background:#fff;color:var(--red);border:1px solid #e8b4ba;padding:6px 14px}
form[action*=delete] button:hover{background:var(--red-l)}
.err{background:#fdecee;color:#a1202f;border:1px solid #f3c1c7;padding:10px 14px;border-radius:8px;margin-bottom:16px}
form.inline{display:inline;margin-left:0}
.cmt{border-top:1px solid var(--line);padding:12px 0}
.cmt p{margin:4px 0 0}
.cmt small{color:var(--mute)}
.cmt b{color:var(--red-d)}
</style></head><body>
<nav><a class="brand" href="/">Go App</a><span class="sp"></span>
{{if .User}}{{if eq .User.Role "admin"}}<a href="/admin">แอดมิน</a>{{end}}<span class="who">สวัสดี {{.User.Username}} ({{.User.Role}})</span>
<form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>ออกจากระบบ</button></form>
{{else}}<a href="/login">เข้าสู่ระบบ</a><a href="/register">สมัครสมาชิก</a>{{end}}</nav><hr>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}{{end}}

{{define "register"}}{{template "head" .}}<h2>สมัครสมาชิก</h2>
<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}">
<input name="username" placeholder="ชื่อผู้ใช้ (3-20 ตัว)" required>
<input name="password" type="password" placeholder="รหัสผ่าน (8-72 ตัว)" required>
<button>สมัคร</button></form></body></html>{{end}}

{{define "login"}}{{template "head" .}}<h2>เข้าสู่ระบบ</h2>
<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}">
<input name="username" placeholder="ชื่อผู้ใช้" required>
<input name="password" type="password" placeholder="รหัสผ่าน" required>
<button>เข้าสู่ระบบ</button></form></body></html>{{end}}

{{define "index"}}{{template "head" .}}<h2>กระทู้ทั้งหมด</h2>
{{if .User}}<div class="box"><h3>ตั้งกระทู้ใหม่</h3>
<form method="post" action="/notes/create"><input type="hidden" name="csrf" value="{{.CSRF}}">
<input name="title" placeholder="หัวข้อ" required><textarea name="content" placeholder="เนื้อหา" required></textarea>
<button>โพสต์กระทู้</button></form></div>{{end}}
{{range .Notes}}<div class="box thread">
<a class="title" href="/notes/view?id={{.ID}}">{{.Title}}</a>
<div class="meta">โดย {{.Owner}} · {{.Created.Format "02/01/2006 15:04"}}</div>
<p class="content">{{short .Content}}</p>
<div class="thread-foot">
<span class="badge">💬 {{.Replies}} ความคิดเห็น</span>
<a href="/notes/view?id={{.ID}}">อ่านต่อ »</a>
{{if and $.User (eq $.User.ID .UserID)}}<a href="/notes/edit?id={{.ID}}">แก้ไข</a>
<form class="inline" method="post" action="/notes/delete"><input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="id" value="{{.ID}}"><button>ลบ</button></form>{{end}}
</div></div>
{{else}}<p>ยังไม่มีกระทู้</p>{{end}}
</body></html>{{end}}

{{define "view"}}{{template "head" .}}
<div class="box post">
<h2>{{.Note.Title}}</h2>
<div class="meta">โดย {{.Note.Owner}} · {{.Note.Created.Format "02/01/2006 15:04"}}</div>
<p class="content">{{.Note.Content}}</p>
<a href="/">« กลับหน้าแรก</a>
{{if and .User (eq .User.ID .Note.UserID)}} | <a href="/notes/edit?id={{.Note.ID}}">แก้ไข</a>
<form class="inline" method="post" action="/notes/delete"><input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="id" value="{{.Note.ID}}"><button>ลบ</button></form>{{end}}
</div>

<div class="box" id="comments">
<h3>ความคิดเห็น ({{len .Comments}})</h3>
{{range $i, $c := .Comments}}<div class="cmt">
<small><b>ความคิดเห็นที่ {{inc $i}}</b> · {{$c.Username}} · {{$c.Created.Format "02/01/2006 15:04"}}</small>
<p class="content">{{$c.Message}}</p></div>
{{else}}<p>ยังไม่มีความคิดเห็น</p>{{end}}

{{if .User}}<form method="post" action="/comments/add">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="note_id" value="{{.Note.ID}}">
<textarea name="message" placeholder="แสดงความคิดเห็น..." required></textarea>
<button>ส่งความคิดเห็น</button></form>
{{else}}<p><a href="/login">เข้าสู่ระบบ</a> เพื่อแสดงความคิดเห็น</p>{{end}}
</div></body></html>{{end}}

{{define "edit"}}{{template "head" .}}<h2>แก้ไขบันทึก</h2>
<form method="post"><input type="hidden" name="csrf" value="{{.CSRF}}">
<input name="title" value="{{.Note.Title}}" required><textarea name="content" required>{{.Note.Content}}</textarea>
<button>บันทึกการแก้ไข</button></form></body></html>{{end}}

{{define "admin"}}{{template "head" .}}<h2>หน้าแอดมิน</h2><h3>ผู้ใช้ทั้งหมด</h3>
{{range .Users}}<div class="box">{{.Username}} ({{.Role}})
{{if ne .Role "admin"}}<form class="inline" method="post" action="/admin/delete-user">
<input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}">
<button>ลบผู้ใช้</button></form>{{end}}</div>{{end}}
<h3>บันทึกทั้งหมด</h3>
{{range .Notes}}<div class="box"><a href="/notes/view?id={{.ID}}"><b>{{.Title}}</b></a> โดย {{.Owner}}
<form class="inline" method="post" action="/admin/delete-note"><input type="hidden" name="csrf" value="{{$.CSRF}}">
<input type="hidden" name="id" value="{{.ID}}"><button>ลบ</button></form></div>{{end}}</body></html>{{end}}
`

var tpl = template.Must(template.New("").Funcs(template.FuncMap{
	// ตัดเนื้อหาให้สั้นลงในหน้าแรก (นับเป็นตัวอักษร ไม่ใช่ byte)
	"short": func(s string) string {
		r := []rune(s)
		if len(r) > 150 {
			return string(r[:150]) + "…"
		}
		return s
	},
	// เลขลำดับคอมเมนต์ (เริ่มที่ 1)
	"inc": func(i int) int { return i + 1 },
}).Parse(pages))

// ---------- Session / Helper ----------
func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func setCookie(w http.ResponseWriter, v string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: v, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: os.Getenv("PROD") == "1", MaxAge: maxAge})
}

func newSession(w http.ResponseWriter, u *User) *Session {
	t := token()
	life := time.Hour // ยังไม่ login: อายุสั้น
	if u != nil {
		life = 24 * time.Hour
	}
	s := &Session{User: u, CSRF: token(), Expires: time.Now().Add(life)}
	mu.Lock()
	if u == nil && len(sessions) >= maxSessions {
		mu.Unlock()
		return s // เต็มแล้ว: ไม่เก็บ session ใหม่ของผู้ไม่ได้ login
	}
	sessions[t] = s
	mu.Unlock()
	setCookie(w, t, int(life.Seconds()))
	return s
}

func dropSession(r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil {
		mu.Lock()
		delete(sessions, c.Value)
		mu.Unlock()
	}
}

func getSession(w http.ResponseWriter, r *http.Request) *Session {
	if c, err := r.Cookie("sid"); err == nil {
		mu.Lock()
		s := sessions[c.Value]
		if s != nil && time.Now().After(s.Expires) {
			delete(sessions, c.Value)
			s = nil
		}
		mu.Unlock()
		if s != nil {
			return s
		}
	}
	return newSession(w, nil)
}

// ล้าง session หมดอายุ กัน memory โตไม่หยุด
func cleaner() {
	for range time.Tick(10 * time.Minute) {
		now := time.Now()
		mu.Lock()
		for k, s := range sessions {
			if now.After(s.Expires) {
				delete(sessions, k)
			}
		}
		mu.Unlock()

		failsMu.Lock()
		for k, f := range fails {
			if now.After(f.until) {
				delete(fails, k)
			}
		}
		failsMu.Unlock()
	}
}

func clientIP(r *http.Request) string {
	if trustProxy {
		// หลัง proxy 1 ชั้น: ใช้ IP ตัวท้ายสุดที่ proxy ต่อให้ (ตัวหน้า ๆ ปลอมได้)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func blocked(key string, max int) bool {
	failsMu.Lock()
	defer failsMu.Unlock()
	f := fails[key]
	return f != nil && f.n >= max && time.Now().Before(f.until)
}

func recordFail(ip string) {
	failsMu.Lock()
	defer failsMu.Unlock()
	f := fails[ip]
	if f == nil || time.Now().After(f.until) {
		f = &failInfo{}
		fails[ip] = f
	}
	f.n++
	f.until = time.Now().Add(5 * time.Minute)
}

func clearFails(ip string) {
	failsMu.Lock()
	delete(fails, ip)
	failsMu.Unlock()
}

// ทุก request ผ่านตรงนี้: ใส่ security header, จำกัดขนาด body, ตรวจ CSRF
func h(fn func(http.ResponseWriter, *http.Request, *Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		if os.Getenv("PROD") == "1" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		s := getSession(w, r)
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if r.FormValue("csrf") != s.CSRF {
				http.Error(w, "CSRF token ไม่ถูกต้อง", 403)
				return
			}
		}
		fn(w, r, s)
	}
}

func render(w http.ResponseWriter, name string, s *Session, p Page) {
	p.User, p.CSRF = s.User, s.CSRF
	if err := tpl.ExecuteTemplate(w, name, p); err != nil {
		log.Println("template:", err)
	}
}

func needLogin(w http.ResponseWriter, r *http.Request, s *Session) bool {
	if s.User == nil {
		http.Redirect(w, r, "/login", 303)
		return false
	}
	return true
}

func needAdmin(w http.ResponseWriter, r *http.Request, s *Session) bool {
	if !needLogin(w, r, s) {
		return false
	}
	if s.User.Role != "admin" {
		http.Error(w, "เฉพาะแอดมินเท่านั้น", 403)
		return false
	}
	return true
}

func allNotes() []Note {
	var list []Note
	rows, err := db.Query(`SELECT n.id,n.user_id,u.username,n.title,n.content,n.created_at,
		(SELECT COUNT(*) FROM comments c WHERE c.note_id=n.id)
		FROM notes n JOIN users u ON u.id=n.user_id ORDER BY n.id DESC`)
	if err != nil {
		log.Println("allNotes:", err)
		return list
	}
	defer rows.Close()
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.UserID, &n.Owner, &n.Title, &n.Content, &n.Created, &n.Replies); err != nil {
			log.Println("scan:", err)
			continue
		}
		list = append(list, n)
	}
	return list
}

// คอมเมนต์ของกระทู้เดียว เรียงจากเก่าไปใหม่
func noteComments(noteID int) []Comment {
	var list []Comment
	rows, err := db.Query(`SELECT c.id,u.username,c.message,c.created_at
		FROM comments c JOIN users u ON u.id=c.user_id
		WHERE c.note_id=? ORDER BY c.id`, noteID)
	if err != nil {
		log.Println("noteComments:", err)
		return list
	}
	defer rows.Close()
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.Username, &c.Message, &c.Created); err != nil {
			log.Println("scan comment:", err)
			continue
		}
		list = append(list, c)
	}
	return list
}

// ---------- Handlers ----------
func register(w http.ResponseWriter, r *http.Request, s *Session) {
	if r.Method == "GET" {
		render(w, "register", s, Page{})
		return
	}
	ip := clientIP(r)
	if blocked("reg:"+ip, 10) {
		render(w, "register", s, Page{Error: "สมัครบ่อยเกินไป กรุณารอ 5 นาที"})
		return
	}
	recordFail("reg:" + ip) // นับทุกครั้งที่กดสมัคร กันสแปมสร้างบัญชี
	u, pw := strings.TrimSpace(r.FormValue("username")), r.FormValue("password")
	n := utf8.RuneCountInString(u)
	if n < 3 || n > 20 || len(pw) < 8 || len(pw) > 72 { // bcrypt รับได้สูงสุด 72 byte
		render(w, "register", s, Page{Error: "ชื่อผู้ใช้ 3-20 ตัว และรหัสผ่าน 8-72 ตัว"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost) // hash รหัสผ่าน
	if err != nil {
		render(w, "register", s, Page{Error: "เกิดข้อผิดพลาด ลองใหม่อีกครั้ง"})
		return
	}
	_, err = db.Exec("INSERT INTO users(username,password,role) VALUES(?,?, 'user')", u, string(hash))
	if err != nil {
		render(w, "register", s, Page{Error: "ชื่อผู้ใช้นี้ถูกใช้แล้ว"})
		return
	}
	http.Redirect(w, r, "/login", 303)
}

func login(w http.ResponseWriter, r *http.Request, s *Session) {
	if r.Method == "GET" {
		render(w, "login", s, Page{})
		return
	}
	ip := clientIP(r)
	if blocked("login:"+ip, 5) {
		render(w, "login", s, Page{Error: "ลองผิดหลายครั้งเกินไป กรุณารอ 5 นาที"})
		return
	}
	var u User
	var hash string
	err := db.QueryRow("SELECT id,username,password,role FROM users WHERE username=?",
		r.FormValue("username")).Scan(&u.ID, &u.Username, &hash, &u.Role)
	if err != nil {
		hash = string(dummyHash) // ไม่พบ user: เทียบกับ hash ปลอม ให้เวลาตอบเท่ากัน
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.FormValue("password"))) != nil || err != nil {
		recordFail("login:" + ip)
		render(w, "login", s, Page{Error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"})
		return
	}
	clearFails("login:" + ip)
	dropSession(r) // สร้าง session ใหม่ทุกครั้งที่ login (กัน session fixation)
	newSession(w, &u)
	http.Redirect(w, r, "/", 303)
}

func logout(w http.ResponseWriter, r *http.Request, s *Session) {
	dropSession(r)
	setCookie(w, "", -1)
	http.Redirect(w, r, "/", 303)
}

func index(w http.ResponseWriter, r *http.Request, s *Session) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	render(w, "index", s, Page{Notes: allNotes()})
}

// หน้าอ่านกระทู้เต็ม ๆ พร้อมคอมเมนต์ (ใครก็เปิดดูได้)
func viewNote(w http.ResponseWriter, r *http.Request, s *Session) {
	id, _ := strconv.Atoi(r.FormValue("id"))
	var n Note
	err := db.QueryRow(`SELECT n.id,n.user_id,u.username,n.title,n.content,n.created_at
		FROM notes n JOIN users u ON u.id=n.user_id WHERE n.id=?`, id).
		Scan(&n.ID, &n.UserID, &n.Owner, &n.Title, &n.Content, &n.Created)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	render(w, "view", s, Page{Note: n, Comments: noteComments(n.ID)})
}

func validNote(t, c string) bool {
	return t != "" && c != "" && utf8.RuneCountInString(t) <= 100 && utf8.RuneCountInString(c) <= 1000
}

func createNote(w http.ResponseWriter, r *http.Request, s *Session) {
	if r.Method != "POST" || !needLogin(w, r, s) {
		return
	}
	t, c := strings.TrimSpace(r.FormValue("title")), strings.TrimSpace(r.FormValue("content"))
	if validNote(t, c) {
		db.Exec("INSERT INTO notes(user_id,title,content) VALUES(?,?,?)", s.User.ID, t, c)
	}
	http.Redirect(w, r, "/", 303)
}

func editNote(w http.ResponseWriter, r *http.Request, s *Session) {
	if !needLogin(w, r, s) {
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	var n Note
	// เช็คเจ้าของ: ต้องเป็น note ของ user ที่ login อยู่เท่านั้น
	err := db.QueryRow("SELECT id,title,content FROM notes WHERE id=? AND user_id=?",
		id, s.User.ID).Scan(&n.ID, &n.Title, &n.Content)
	if err != nil {
		http.Error(w, "ไม่มีสิทธิ์แก้ไขข้อมูลนี้", 403)
		return
	}
	if r.Method == "GET" {
		render(w, "edit", s, Page{Note: n})
		return
	}
	t, c := strings.TrimSpace(r.FormValue("title")), strings.TrimSpace(r.FormValue("content"))
	if validNote(t, c) {
		db.Exec("UPDATE notes SET title=?,content=? WHERE id=? AND user_id=?", t, c, id, s.User.ID)
	}
	http.Redirect(w, r, "/notes/view?id="+strconv.Itoa(id), 303)
}

func deleteNote(w http.ResponseWriter, r *http.Request, s *Session) {
	if r.Method != "POST" || !needLogin(w, r, s) {
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	db.Exec("DELETE FROM notes WHERE id=? AND user_id=?", id, s.User.ID) // ลบได้เฉพาะของตัวเอง
	http.Redirect(w, r, "/", 303)
}

// เพิ่มคอมเมนต์ในกระทู้ แล้วเด้งกลับไปส่วนคอมเมนต์
func addComment(w http.ResponseWriter, r *http.Request, s *Session) {
	if r.Method != "POST" || !needLogin(w, r, s) {
		return
	}
	id, _ := strconv.Atoi(r.FormValue("note_id"))
	m := strings.TrimSpace(r.FormValue("message"))
	if m != "" && utf8.RuneCountInString(m) <= 500 {
		// ถ้า note_id ไม่มีอยู่จริง foreign key จะปฏิเสธเอง
		if _, err := db.Exec("INSERT INTO comments(note_id,user_id,message) VALUES(?,?,?)", id, s.User.ID, m); err != nil {
			log.Println("addComment:", err)
		}
	}
	http.Redirect(w, r, "/notes/view?id="+strconv.Itoa(id)+"#comments", 303)
}

func admin(w http.ResponseWriter, r *http.Request, s *Session) {
	if !needAdmin(w, r, s) {
		return
	}
	var us []User
	rows, err := db.Query("SELECT id,username,role FROM users ORDER BY id")
	if err != nil {
		log.Println("admin:", err)
	} else {
		defer rows.Close()
		for rows.Next() {
			var u User
			rows.Scan(&u.ID, &u.Username, &u.Role)
			us = append(us, u)
		}
	}
	render(w, "admin", s, Page{Users: us, Notes: allNotes()})
}

func adminDeleteUser(w http.ResponseWriter, r *http.Request, s *Session) {
	if r.Method != "POST" || !needAdmin(w, r, s) {
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	var role string
	if db.QueryRow("SELECT role FROM users WHERE id=?", id).Scan(&role) == nil && role != "admin" {
		db.Exec("DELETE FROM comments WHERE user_id=?", id)
		db.Exec("DELETE FROM notes WHERE user_id=?", id)
		db.Exec("DELETE FROM users WHERE id=? AND role!='admin'", id)
		// เตะ session ของคนที่ถูกลบออกทันที
		mu.Lock()
		for k, ss := range sessions {
			if ss.User != nil && ss.User.ID == id {
				delete(sessions, k)
			}
		}
		mu.Unlock()
	}
	http.Redirect(w, r, "/admin", 303)
}

func adminDeleteNote(w http.ResponseWriter, r *http.Request, s *Session) {
	if r.Method != "POST" || !needAdmin(w, r, s) {
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	db.Exec("DELETE FROM notes WHERE id=?", id) // คอมเมนต์ของกระทู้ถูกลบตามอัตโนมัติ (ON DELETE CASCADE)
	http.Redirect(w, r, "/admin", 303)
}

// ---------- เชื่อม MySQL (XAMPP) ----------
func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func connectDB() {
	user := env("DB_USER", "root")
	pass := os.Getenv("DB_PASS") // XAMPP ค่าเริ่มต้น root ไม่มีรหัสผ่าน
	host := env("DB_HOST", "127.0.0.1:3307")
	name := env("DB_NAME", "gonotes")
	tlsOpt := ""
	if v := os.Getenv("DB_TLS"); v != "" { // ฐานข้อมูลบนคลาวด์ (เช่น Aiven) ต้องใช้ TLS: ตั้ง DB_TLS=skip-verify
		tlsOpt = "&tls=" + v
	}

	// 1) สร้างฐานข้อมูลให้อัตโนมัติถ้ายังไม่มี
	boot, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/?charset=utf8mb4%s", user, pass, host, tlsOpt))
	if err != nil {
		log.Fatal(err)
	}
	if _, err := boot.Exec("CREATE DATABASE IF NOT EXISTS `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		// บนโฮสบางที่ไม่อนุญาตสร้างฐานข้อมูล (มีให้แล้ว) จึงเตือนไว้ก่อน แล้วลองเชื่อมต่อจริงต่อ
		log.Println("สร้างฐานข้อมูลอัตโนมัติไม่ได้ (ข้ามไปลองเชื่อมต่อต่อ):", err)
	}
	boot.Close()

	// 2) เชื่อมฐานข้อมูลจริง
	db, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&parseTime=true&loc=Local%s", user, pass, host, name, tlsOpt))
	if err != nil {
		log.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		log.Fatal("เชื่อมต่อฐานข้อมูลไม่ได้ (เช็ก DB_HOST/DB_USER/DB_PASS/DB_NAME และ MySQL เปิดอยู่ไหม): ", err)
	}
	db.SetMaxOpenConns(10)

	// 3) สร้างตาราง (MySQL driver รันทีละคำสั่ง)
	// หมายเหตุ: ถ้ามีตาราง comments แบบเก่า (ไม่มี note_id) ให้รัน DROP TABLE comments; ก่อน 1 ครั้ง
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users(
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL UNIQUE,
			password VARCHAR(100) NOT NULL,
			role VARCHAR(10) NOT NULL DEFAULT 'user'
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS notes(
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			title VARCHAR(100) NOT NULL,
			content TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
		`CREATE TABLE IF NOT EXISTS comments(
			id INT AUTO_INCREMENT PRIMARY KEY,
			note_id INT NOT NULL,
			user_id INT NOT NULL,
			message VARCHAR(500) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}
	// ถ้ามีตาราง comments แบบเก่า (ไม่มี note_id) ให้ลบทิ้งแล้วสร้างใหม่ให้อัตโนมัติ
	var hasTable, hasCol int
	db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema=DATABASE() AND table_name='comments'`).Scan(&hasTable)
	db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema=DATABASE() AND table_name='comments' AND column_name='note_id'`).Scan(&hasCol)
	if hasTable > 0 && hasCol == 0 {
		log.Println("พบตาราง comments แบบเก่า กำลังสร้างใหม่ให้ (คอมเมนต์เก่าจะหายไป)")
		if _, err := db.Exec("DROP TABLE comments"); err != nil {
			log.Fatal(err)
		}
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			log.Fatal(err)
		}
	}
}

// ---------- main ----------
func main() {
	connectDB()
	go cleaner()
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

	// สร้างแอดมินเริ่มต้น (รหัสผ่านตั้งผ่าน env ADMIN_PASSWORD)
	pw := os.Getenv("ADMIN_PASSWORD")
	if pw == "" {
		pw = "admin12345"
		log.Println("คำเตือน: ใช้รหัสแอดมินเริ่มต้น ควรตั้ง ADMIN_PASSWORD ก่อนขึ้นเซิร์ฟเวอร์จริง")
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	db.Exec("INSERT IGNORE INTO users(username,password,role) VALUES('admin',?, 'admin')", string(hash))

	http.HandleFunc("/", h(index))
	http.HandleFunc("/register", h(register))
	http.HandleFunc("/login", h(login))
	http.HandleFunc("/logout", h(logout))
	http.HandleFunc("/notes/view", h(viewNote))
	http.HandleFunc("/notes/create", h(createNote))
	http.HandleFunc("/notes/edit", h(editNote))
	http.HandleFunc("/notes/delete", h(deleteNote))
	http.HandleFunc("/comments/add", h(addComment))
	http.HandleFunc("/admin", h(admin))
	http.HandleFunc("/admin/delete-user", h(adminDeleteUser))
	http.HandleFunc("/admin/delete-note", h(adminDeleteNote))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("รันที่ http://localhost:" + port)
	srv := &http.Server{
		Addr:              ":" + port,
		ReadHeaderTimeout: 5 * time.Second, // กัน slowloris
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	log.Fatal(srv.ListenAndServe())
}
