package main

import (
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

// seed random number generator for IDs
var rand_gen *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

// load secret from .env file and make new cookie store
var secret, _ = os.ReadFile(".env")
var store = sessions.NewCookieStore([]byte(secret))

// set funcMap for custom functions while parsing HTTP templates
var funcMap template.FuncMap = template.FuncMap{
	"mod": func(a int, b int) int { return a % b },
	"add": func(a int, b int) int { return a + b },
	"len": func(v []*Article) int { return len(v) },
}

type Article struct {
	// id of the article, visible in URL
	Title  string
	Author string
	ID     string
	// creation date of the article represented as unix epoch time
	CreationDateEpoch string
	// date that the article was last edited
	EditDateEpoch string
	// tags for the article (north america, south america, asia, africa, europe, oceania)
	// abbreviated to "na", "sa", "eu", "af", "as", "oc"
	Tags []string
	// name of cover image so that /assets/img/CoverImageName points to image location
	CoverImageName string
	// actual content of the article
	Body     string
	HtmlBody template.HTML
	// used for editing article
	TagsInt []int
}

type User struct {
	Username string
	Email    string
	// HashedPassword saved in user folder
	// automatically salted with bcrypt
	HashedPassword []byte
}

// used in http template for homepage
type Homepage struct {
	// first 2 articles on homepage (big card)
	Header []*Article
	// rest of the articles (small card)
	Body []*Article
}

// used in http template for section (continent pages)
type Section struct {
	// name of section (North America, Europe, etc.)
	SectionName string
	// articles to display in section
	Articles []*Article
}

// can call with [*Article object name].save()
// such as index.save()
// no parameters, returns error
func (a *Article) save() error {
	/*
	   Article is saved in text file in the same order as class definition (excluding HtmlBody)
	   - Title
	   - Author
	   - ID
	   - CreationDateEpoch
	   - EditDateEpoch
	   - Tags
	   - CoverImageName
	   - Body
	*/
	filename := "articles/" + a.ID + ".txt"
	content_str := a.Title + "\n" +
		a.Author + "\n" +
		a.ID + "\n" +
		string(a.CreationDateEpoch) + "\n" +
		string(a.EditDateEpoch) + "\n"

	for i := 0; i < len(a.Tags); i++ {
		content_str = content_str + a.Tags[i] + " "
	}
	content_str += "\n" + a.CoverImageName + "\n" + a.Body
	content := []byte(content_str)
	return os.WriteFile(filename, content, 0600)
}

// string parameter, returns *Page and error
func loadPage(id string) (*Article, error) {
	filename := "articles/" + id + ".txt"
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")

	title := strings.TrimSpace(lines[0])
	author := strings.TrimSpace(lines[1])
	articleID := strings.TrimSpace(lines[2])
	creationDateEpoch := strings.TrimSpace(lines[3])
	editDateEpoch := strings.TrimSpace(lines[4])
	tags := strings.Split(strings.TrimSpace(lines[5]), " ")
	coverImageName := strings.TrimSpace(lines[6])
	body := strings.TrimSpace(strings.Join(lines[7:], "\n"))
	return &Article{Title: title, Author: author, ID: articleID, CreationDateEpoch: creationDateEpoch,
		EditDateEpoch: editDateEpoch, Tags: tags, CoverImageName: coverImageName, Body: body}, nil
}

func (u *User) saveUser() error {
	userStr := u.Username + "\n" + u.Email + "\n" + string(u.HashedPassword)
	userBytes := []byte(userStr)
	filename := "users/" + u.Username + ".bin"
	return os.WriteFile(filename, userBytes, 0600)
}

func loadUser(username string) (*User, error) {
	filename := "users/" + username + ".bin"
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	u := strings.TrimSpace(lines[0])
	e := strings.TrimSpace(lines[1])
	hp := []byte(strings.TrimSpace(lines[2]))
	return &User{Username: u, Email: e, HashedPassword: hp}, nil
}

func renderTemplate(w http.ResponseWriter, tmpl string, a *Article) {
	t, _ := template.ParseFiles("templates/" + tmpl + ".html")
	a.HtmlBody = template.HTML(a.Body)
	t.Execute(w, a)
}

func renderTemplateHome(w http.ResponseWriter, h Homepage) {
	t, err := template.New("index").Funcs(funcMap).ParseFiles("templates/index.html")
	if err != nil {
		fmt.Println("Error in renderTemplateHome preparing template")
		fmt.Println(err)
		return
	}

	err = t.Execute(w, h)
	if err != nil {
		fmt.Println("Error in renderTemplateHome preparing template")
		fmt.Println(err)
		return
	}
	fmt.Println("Loaded template successfully")
}

func renderTemplateSection(w http.ResponseWriter, s Section) {
	t, err := template.New("section").Funcs(funcMap).ParseFiles("templates/section.html")
	if err != nil {
		fmt.Println("Error in renderTemplateSection preparing template")
		fmt.Println(err)
		return
	}

	err = t.Execute(w, s)
	if err != nil {
		fmt.Println("Error in renderTemplateSection preparing template")
		fmt.Println(err)
		return
	}
	fmt.Println("Loaded template successfully")
}

func renderTemplateLogin(w http.ResponseWriter, tmpl string) {
	t, _ := template.ParseFiles("templates/" + tmpl + ".html")
	t.Execute(w, nil)
}

func main() {
	// requests for static content in assets folder
	fs := http.FileServer(http.Dir("./assets"))
	http.Handle("/assets/", http.StripPrefix("/assets/", fs))
	http.HandleFunc("/articles/", articleHandler)
	http.HandleFunc("/section/", sectionHandler)
	http.HandleFunc("/edit/", editHandler)
	http.HandleFunc("/save/", saveHandler)
	http.HandleFunc("/login/", loginHandler)
	http.HandleFunc("/logout/", logoutHandler)
	http.HandleFunc("/auth/", authHandler)
	http.HandleFunc("/new_user/", newUserHandler)
	http.HandleFunc("/new_user_created/", newUserCreatedHandler)
	http.HandleFunc("/", homeHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
