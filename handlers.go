package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

func articleHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/articles/"):(len(r.URL.Path) - 5)]
	p, err := loadPage(id)
	if err != nil {
		http.Redirect(w, r, "/edit/"+id, http.StatusFound)
		return
	}
	renderTemplate(w, "article", p)
}

func sectionHandler(w http.ResponseWriter, r *http.Request) {
	sections := [][]string{
		{"north_america", "na", "North America"},
		{"europe", "eu", "Europe"},
		{"asia", "as", "Asia"},
		{"africa", "af", "Africa"},
		{"south_america", "so", "South America"},
		{"oceania", "oc", "Oceania"},
	}

	url_tag := r.URL.Path[len("/section/"):]
	section_tag := ""
	section_name := ""
	for i := 0; i < len(sections); i++ {
		if url_tag == sections[i][0] {
			section_tag = sections[i][1]
			section_name = sections[i][2]
			break
		}
	}
	if section_tag == "" {
		fmt.Println("Error: section not found")
		return
	}

	var sectionArticleArray []*Article
	// iterate over all articles
	err := filepath.Walk("articles/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Check if the file is not a directory
		if !info.IsDir() {
			// Read the file content
			p, _ := loadPage(info.Name()[:len(info.Name())-4])
			// Append the file content as a string to the slice if the tag is correct
			if slices.Contains(p.Tags, section_tag) {
				sectionArticleArray = append(sectionArticleArray, p)
			}
		}
		return nil
	})

	// sort sectionArticleArray in descending order so that most recent articles are towards top of page
	sort.Slice(sectionArticleArray, func(i, j int) bool {
		val1, err1 := strconv.Atoi(sectionArticleArray[i].CreationDateEpoch)
		val2, err2 := strconv.Atoi(sectionArticleArray[j].CreationDateEpoch)
		if err1 != nil || err2 != nil {
			fmt.Println("Error converting string to int while sorting list in sectionHandler")
			// error converting string to int -> give placeholder answer of false
			return false
		}
		return val1 < val2
	})

	if err != nil {
		fmt.Println("Error in sectionHandler")
		fmt.Println(err)
		return
	}

	// limit home page to 17 articles (2 featured articles in big cards at top + 5 rows of 3 articles in small cards)
	if len(sectionArticleArray) > 17 {
		sectionArticleArray = sectionArticleArray[:17]
	}

	sectionStruct := Section{SectionName: section_name, Articles: sectionArticleArray}

	renderTemplateSection(w, sectionStruct)
}

func editHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	fmt.Print("\n\n\nc")
	requested_id := ""
	if len(r.URL.Path) > (len("/edit/") + 5) {
		requested_id = r.URL.Path[len("/edit/") : len(r.URL.Path)-5]
	} else {
		requested_id = ""
	}
	p, err := loadPage(requested_id)
	if err != nil {
		fmt.Print("\n\n\nb")
		// get a random ID and make sure it does not already exist
		id := strconv.Itoa(int(rand_gen.Int31()))
		_, err := os.ReadFile("articles/" + id + ".txt")
		// generate IDs until we get a valid one
		for err == nil {
			id = strconv.Itoa(int(rand_gen.Int31()))
			_, err = os.Stat("articles/" + id + ".txt")
		}
		p = &Article{ID: id, TagsInt: []int{0, 0, 0, 0, 0, 0}}
	} else {
		fmt.Print("\n\n\na")
		p.TagsInt = []int{0, 0, 0, 0, 0, 0}
		sections := []string{"na", "eu", "as", "af", "so", "oc"}
		for i := 0; i < len(p.Tags); i++ {
			if p.Tags[i] == sections[i] {
				p.TagsInt[i] = 1
			}
		}
	}
	renderTemplate(w, "edit", p)
}

func saveHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// max file size 1 MiB
	r.ParseMultipartForm(1 << 20)

	id := r.URL.Path[len("/save/"):]
	title := r.FormValue("title")
	author := r.FormValue("author")

	tags := []string{}

	tag_list := []string{"na", "sa", "eu", "af", "as", "oc"}
	// iterate through tags checkboxes
	for i := 0; i < len(tag_list); i++ {
		if r.FormValue(tag_list[i]) == "on" {
			tags = append(tags, tag_list[i])
		}
	}

	// handle file (cover image) upload
	file, header, _ := r.FormFile("coverImage")
	defer file.Close()

	fmt.Printf("Uploaded File: %+v\n", header.Filename)
	fmt.Printf("File Size: %+v\n", header.Size)
	fmt.Printf("MIME Header: %+v\n", header.Header)

	// create a destination file
	img_name := strings.TrimSpace("assets/img/" + id + filepath.Ext(header.Filename))
	dst, err := os.Create(img_name)
	if err != nil {
		fmt.Println("Error Retrieving the File 1")
		fmt.Println(err)
		return
	}
	defer dst.Close()

	// upload the file to destination path
	bits_written, err := io.Copy(dst, file)
	if bits_written == 0 || err != nil {
		fmt.Println("Error Retrieving the File 2")
		fmt.Println(err)
		return
	}
	fmt.Println("File uploaded successfully")

	body := strings.Replace(r.FormValue("body"), "\n", "\n<br>", -1)
	creationDateEpoch := strconv.Itoa(int(time.Now().Unix()))
	editDateEpoch := "0"
	p := &Article{ID: id, Title: title, Author: author, CreationDateEpoch: creationDateEpoch,
		EditDateEpoch: editDateEpoch, Tags: tags, CoverImageName: "/" + img_name, Body: body}
	p.save()
	http.Redirect(w, r, "/articles/"+id, http.StatusFound)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplateLogin(w, "login")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Values["username"] = ""
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   0, // MaxAge 0 -> cookie expires immediately
		HttpOnly: true,
		Secure:   true,
	}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password_attempt := r.FormValue("password")
	user, err := loadUser(username)
	if err != nil {
		fmt.Println("Error in authHandler")
		http.Redirect(w, r, "/login/", http.StatusFound)
		return
	}

	correct_hash := user.HashedPassword
	err = bcrypt.CompareHashAndPassword([]byte(correct_hash), []byte(password_attempt))
	if err != nil {
		// fmt.Println("Password and hash do not match. Redirecting to login page")
		http.Redirect(w, r, "/login/", http.StatusFound)
	}

	// if execution is here, user successfully logged in
	// make encrypted session store
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = true
	session.Values["username"] = username
	session.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60 * 24 * 7, // 1 week
		HttpOnly: true,
		Secure:   true,
	}
	session.Save(r, w)
	fmt.Fprintln(w, "Logged in successfully!")
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	var articleArray []*Article
	// iterate over all articles
	err := filepath.Walk("articles/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Check if the file is not a directory
		if !info.IsDir() && info.Name() != ".gitignore" {
			// Read the file content
			fmt.Printf("Loading file: %s\n", info.Name())
			p, _ := loadPage(info.Name()[:len(info.Name())-4])
			// Append the file content as a string to the slice
			articleArray = append(articleArray, p)
		}
		return nil
	})

	// sort sectionArticleArray in descending order so that most recent articles are towards top of page
	sort.Slice(articleArray, func(i, j int) bool {
		val1, err1 := strconv.Atoi(articleArray[i].CreationDateEpoch)
		val2, err2 := strconv.Atoi(articleArray[j].CreationDateEpoch)
		if err1 != nil || err2 != nil {
			fmt.Println("Error converting string to int while sorting list in sectionHandler")
			// give placeholder answer
			return false
		}
		return val1 > val2
	})
	header := articleArray[:2]
	body := articleArray[2:]
	homepageStruct := Homepage{Header: header, Body: body}

	if err != nil {
		fmt.Println("Error in homeHandler")
		fmt.Println(err)
		return
	}

	renderTemplateHome(w, homepageStruct)
}

func newUserHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplateLogin(w, "new_user")
}

func newUserCreatedHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	hash, _ := HashPassword(password)
	u := User{Username: username, Email: "", HashedPassword: []byte(hash)}
	u.saveUser()
	fmt.Println("user created")
	http.Redirect(w, r, "/login/", http.StatusFound)
}
