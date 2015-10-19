package backend

import (
    "encoding/json"
    "net/http"

    "appengine"
    "appengine/datastore"
    "appengine/mail"
    "fmt"
    "crypto/rand"
    "io"
    "reflect"
    "strings"
    "log"
    "github.com/pmylund/sortutil"
)

type Team struct {
    Id          string `json:"id"`
    Domain      string `json:"domain"`
}

type Project struct {
    Id          string `json:"id"`
    Name        string `json:"name"`
}

type ProjectUser struct {
    ProjectId   string `json:"projectId"`
    UserId      string `json:"userId"`
}

type User struct {
    Id          string `json:"id"`
    FirstName   string `json:"firstName"`
    LastName    string `json:"lastName"`
    Email       string `json:"email"`
    Lat         string `json:"lat"`
    Lng         string `json:"lng"`
    Avatar      string `json:"avatar"`
    TeamId      string `json:"teamId"`
    IsOnline    bool   `json:"isOnline"`
}

type Login struct {
    UserId          string `json:"userId"`
    Username        string `json:"username"`
    Password        string `json:"password"`
}

type Message struct {
    From        string `json:"from"`
    To          string `json:"to"`
    Message     string `json:"message"`
    IsNew       bool   `json:"isNew"`
    TimeStamp   int64  `json:"timeStamp"`
}

func init() {
    http.HandleFunc("/api/addUser", errorHandler(addUser))
    http.HandleFunc("/api/deleteUser", errorHandler(deleteUser))
    http.HandleFunc("/api/users", errorHandler(getUsers))
    http.HandleFunc("/api/addTeam", errorHandler(addTeam))
    http.HandleFunc("/api/teams", errorHandler(getTeams))
    http.HandleFunc("/api/sendMessage", errorHandler(sendMessage))
    http.HandleFunc("/api/readMessages", errorHandler(readMessages))
    http.HandleFunc("/api/messages", errorHandler(getMessages))
    http.HandleFunc("/api/login", errorHandler(login))
    http.HandleFunc("/api/online", errorHandler(online))
    http.HandleFunc("/api/offline", errorHandler(offline))
}

func errorHandler(f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        err := f(w, r)
        if err != nil {
            c := appengine.NewContext(r)
            c.Errorf("error: %v", err)
            getJson(w, struct { Error string `json:"error"` }{err.Error(), }, http.StatusInternalServerError)
        }
    }
}

func login(w http.ResponseWriter, r *http.Request) error {
    c := appengine.NewContext(r)

    l := struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }{}
    if err := json.NewDecoder(r.Body).Decode(&l); err!= nil {
        return getJson(w, struct { Error string `json:"error"` }{err.Error(), }, http.StatusBadRequest)
    }
    q := datastore.NewQuery("Login").Filter("Username =", l.Username).Filter("Password =", l.Password)

    login := []Login{};
    if _, err := q.GetAll(c, &login); err != nil {
        return err
    }

    if len(login) == 0 {
        return getJson(w,  nil, http.StatusOK)
    } else {
        return getJson(w, struct { Id string `json:"id"` }{login[0].UserId, }, http.StatusOK)
    }
}

func online (w http.ResponseWriter, r *http.Request) error {
    return changeStatus(w, r, true)
}

func offline (w http.ResponseWriter, r *http.Request) error {
    return changeStatus(w, r, false)
}

func changeStatus(w http.ResponseWriter, r *http.Request, status bool) error {
    c := appengine.NewContext(r)
    id := r.Header.Get("id")

    q := datastore.NewQuery("User").Filter("Id =", id)

    users := []User{};
    if keys, err := q.GetAll(c, &users); err != nil {
        return err
    } else {
        for i:= range keys {
            users[i].IsOnline = status;
            if _, err := datastore.Put(c, keys[i], &users[i]); err != nil {
                return err
            }

        }
    }

    return getJson(w, struct { Id string `json:"id"` }{users[0].Id, }, http.StatusOK)
}


func readMessages(w http.ResponseWriter, r *http.Request) error {
    c := appengine.NewContext(r)
    id := r.Header.Get("id")

    m := struct{ Sender string `json:"sender"`}{}
    if err := json.NewDecoder(r.Body).Decode(&m); err!= nil {
        return getJson(w, struct { Error string `json:"error"` }{err.Error(), }, http.StatusBadRequest)
    }

    q := datastore.NewQuery("Message").Filter("To =", id).Filter("From =", m.Sender)

    messages := []Message{};
    if keys, err := q.GetAll(c, &messages); err != nil {
        return err
    } else {
        for i:= range keys {
            messages[i].IsNew = false;
            if messages[i].TimeStamp > 0 {
                if _, err := datastore.Put(c, keys[i], &messages[i]); err != nil {
                    return err
                }
            }
        }
    }

    return getJson(w, struct { Count int `json:"count"` }{len(messages), }, http.StatusOK)
}

func sendMessage(w http.ResponseWriter, r *http.Request) error {
    return add(w, r, reflect.TypeOf(Message{}), "Message");
}

func getMessages(w http.ResponseWriter, r *http.Request) error {
    c := appengine.NewContext(r)
    id := r.Header.Get("id")

    message := []Message{}

    q := datastore.NewQuery("Message").Filter("To =", id)

    if _, err := q.GetAll(c, &message); err != nil {
        return err
    }

    q = datastore.NewQuery("Message").Filter("From =", id)

    if _, err := q.GetAll(c, &message); err != nil {
        return err
    }

    sortutil.AscByField(message, "TimeStamp")

    return getJson(w, message, http.StatusOK)
}

func addTeam(w http.ResponseWriter, r *http.Request) error {
    return add(w, r, reflect.TypeOf(Team{}), "Team");
}

func getTeamByDomain(c appengine.Context, domain string) (string, error) {
    q := datastore.NewQuery("Team").Filter("Domain =", domain).KeysOnly().Limit(1)

    keys, err := q.GetAll(c, []Team{})
    if err != nil {
        return "", err
    }
    if len(keys) == 0 {
        return "", nil
    }

    return keys[0].StringID(), nil
}

func getTeams(w http.ResponseWriter, r *http.Request) error {
    return getAll(w, r, reflect.TypeOf([]Team{}), "Team");
}

func getUsers(w http.ResponseWriter, r *http.Request) error {
    return getAll(w, r, reflect.TypeOf([]User{}), "User");
}

func addUser(w http.ResponseWriter, r *http.Request) error {
    c := appengine.NewContext(r)
    u := User{}
    if err := json.NewDecoder(r.Body).Decode(&u); err!= nil {
        return getJson(w, struct { Error string `json:"error"` }{err.Error(), }, http.StatusBadRequest)
    }
    domain := strings.Split(u.Email, "@")
    u.Avatar = Url(u.Email)
    log.Println(domain[1])
    if teamId, err := getTeamByDomain(c, domain[1]); err != nil {

    } else {

        if teamId != "" {
            if u.TeamId != "" && u.TeamId != teamId {
                return getJson(w, struct { Error string `json:"error"` }{"Domain is not matching with team", }, http.StatusBadRequest)
            } else if u.TeamId == "" {
                u.TeamId = teamId
            }
        } else {
            if id, err := newUUID(); err != nil {
                return err
            } else {
                t := Team{Id:id, Domain:domain[1]}

                if key, err := datastore.Put(c, datastore.NewKey(c, "Team", id, 0, nil), &t); err != nil {
                    return err
                } else {
                    u.TeamId = key.StringID()
                }
            }
        }
    }

    if u.Id == "" {
        if id, err := newUUID(); err != nil {
            return err
        } else {
            u.Id = id
        }
    }

    if _, err := datastore.Put(c, datastore.NewKey(c, "User", u.Id, 0, nil), &u); err != nil {
        return err
    }

    login := Login{}
    login.Username = domain[0]
    login.Password = newPassword(8)
    login.UserId = u.Id
    if _, err := datastore.Put(c, datastore.NewKey(c, "Login", u.Id, 0, nil), &login); err != nil {
        return err
    }

    msg := &mail.Message{
        Sender:  "levente.albert@gmail.com",
        To:      []string{ u.FirstName + " " + u.LastName + "<" + u.Email + ">"},
        Subject: "Welcome to Mesi!",
        Body:    "New account has been created username:" + login.Username + " password:" + login.Password,
    }
    if err := mail.Send(c, msg); err != nil {
        return err
    }

    return getJson(w, struct { Id string `json:"id"` }{u.Id, }, http.StatusCreated)
}

func deleteUser(w http.ResponseWriter, r *http.Request) error {
    return delete(w, r, "User",r.FormValue("id"))
}

func add(w http.ResponseWriter, r *http.Request, t reflect.Type, entityName string) error {
    c := appengine.NewContext(r)
    entity := reflect.New(t).Interface()

    if err := json.NewDecoder(r.Body).Decode(entity); err!= nil {
        return getJson(w, struct { Error string `json:"error"` }{err.Error(), }, http.StatusBadRequest)
    }

    id, err := newUUID()
    if err != nil {
        return err
    }

    key, err := datastore.Put(c, datastore.NewKey(c, entityName, id, 0, nil), entity)
    if err != nil {
        return err
    }

    return getJson(w, struct { Id string `json:"id"` }{key.StringID(), }, http.StatusCreated)
}

func getAll(w http.ResponseWriter, r *http.Request, t reflect.Type, entityName string) (error) {
    c := appengine.NewContext(r)
    id := ""//r.Header.Get("id")

    entity := reflect.New(t).Interface()

    q := datastore.NewQuery(entityName)

    if id != "" {
        q = q.Filter("Id >", id)
    }

    if _, err := q.GetAll(c, entity); err != nil {
        return err
    }

    if id != "" {
        q = datastore.NewQuery(entityName).Filter("Id <", id)

        if _, err := q.GetAll(c, entity); err != nil {
            return err
        }
    }

    return getJson(w, entity, http.StatusOK)
}

func delete(w http.ResponseWriter, r *http.Request, entityName string, id string) error {
    log.Print(r.Method)
    if (r.Method != "DELETE") {
        return getJson(w, struct { Error string `json:"error"` }{"Method Not Allowed", }, http.StatusMethodNotAllowed)
    }
    c := appengine.NewContext(r)
    key := datastore.NewKey(c, entityName, id, 0, nil)
    if err := datastore.Delete(c, key); err != nil {
        return err
    } else {
        return getJson(w, struct { DeletedId string `json:"deletedId"` }{id, }, http.StatusOK)
    }
}

func getJson(w http.ResponseWriter, v interface{}, status int) error {
    w.Header().Set("Content-Type", "application/json; charset=UTF-8")
    w.WriteHeader(status)
    if err := json.NewEncoder(w).Encode(v); err != nil {
        return err
    }
    return nil
}

func newUUID() (string, error) {
    uuid := make([]byte, 16)
    n, err := io.ReadFull(rand.Reader, uuid)
    if n != len(uuid) || err != nil {
        return "", err
    }
    // variant bits; see section 4.1.1
    uuid[8] = uuid[8]&^0xc0 | 0x80
    // version 4 (pseudo-random); see section 4.1.3
    uuid[6] = uuid[6]&^0xf0 | 0x40
    return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+,.?/:;{}[]`~")

func newPassword(length int) string {
    return rand_char(length, StdChars)
}

func rand_char(length int, chars []byte) string {
    new_pword := make([]byte, length)
    random_data := make([]byte, length+(length/4)) // storage for random bytes.
    clen := byte(len(chars))
    maxrb := byte(256 - (256 % len(chars)))
    i := 0
    for {
        if _, err := io.ReadFull(rand.Reader, random_data); err != nil {
            panic(err)
        }
        for _, c := range random_data {
            if c >= maxrb {
                continue
            }
            new_pword[i] = chars[c%clen]
            i++
            if i == length {
                return string(new_pword)
            }
        }
    }
    panic("unreachable")
}