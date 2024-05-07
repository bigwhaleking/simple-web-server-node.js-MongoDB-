const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
require('dotenv').config();
app.use(express.urlencoded({extended: true}));
app.use(session({secret:'secret', resave: true, saveUninitialized: false}));
app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', 'ejs');

//MongoBD
const MongoClient = require('mongodb').MongoClient;
const db_id = process.env.DB_ID;
const db_pw = process.env.DB_PW;
const db_cluster = process.env.DB_CLUSTER;
const server_port = process.env.SEVER_PORT;
const db_url = 'mongodb+srv://' + db_id + ':' + db_pw + '@' + db_cluster + '.ua1riqy.mongodb.net/?retryWrites=true&w=majority';
let db;

MongoClient.connect(db_url, (error, client) => {
    if (error) {
        return console.log(error);
    } else {
        app.listen(server_port, () => {
            db = client.db('regis');
            console.log('server on');
        })
    }
})

//메인 페이지
app.get('/',function(req, res){
    res.render('index.ejs');
});

//first페이지
app.get('/first',function(req, res){
    res.render('first.ejs');
});

//register페이지
app.get('/register',function(req, res){
    res.render('register.ejs');
});

//mypage페이지
app.get('/mypage',loginCheck, (req, res)=>{
    res.render('mypage.ejs', {userSession: req.user});
});

//로그인 했는지 확인
function loginCheck(req, res, next){
    if(req.user){
        next()
    } else {
        res.send('로그인안함 <a href=\"/login\">로그인</a>');
    }
}

//아이디,비밀번호 DB등록
app.post('/register',(req, res)=>{
    
    console.log('아이디 등록 중');

    let id = req.body.id;
    let pw = req.body.pw;
    const saltRoudns = 10;

    bcrypt.hash(pw, saltRoudns, (err, hash)=>{
        try{
        db.collection('login').findOne({id:id}, (error, result)=>{
            if(result) {
                // 가입실패
                res.send("<script>alert('아이디 생성 실패'); location.href='/register';</script>");  
                console.log('아이디 등록 실패');
            } else {
                // 가입성공
                db.collection('login').insertOne({id: id, pw: hash}, (error, result)=>{
                    res.send("<script>alert('아이디 생성 성공'); location.href='/login';</script>");  
                    console.log('아이디 등록 성공');
                })
            }
        })
        }catch{
            console.log('err : '+err);
        }
    })

});

//로그인
app.get('/login', (req, res)=>{
    res.render('login.ejs');
    console.log('로그인 중');

    passport.use(new LocalStrategy({
        usernameField: 'id',
        passwordField: 'pw',
        session: true,
    }, (input_id, input_pw, done)=>{
        db.collection('login').findOne({id: input_id}, (error, user)=>{
            if(error) return done(error);
            if(!user) {
                console.log('아이디 없음');
                return done(null, user);
            }
            //암호화된 비밀번호 학인 기능
            bcrypt.compare(input_pw, user.pw, (error, result)=>{
                try {
                    if(result) {
                        console.log('로그인 성공');
                        return done(null, user);
                    } else {
                        console.log('비번틀림1');
                        return done(null, false, {message: '비번틀림'});
                    }
                } catch(error) {
                    return done(error);
                }
            })
        })
    }));
})

app.post('/login', passport.authenticate('local', {
    failureRedirect: '/loginFail'
}), (req, res) => {
    res.send("<script>alert('hihi'); location.href='/';</script>");
})

app.get('/loginFail', (req, res)=>{
    res.send("<script>location.href='/login';</script>");
})

passport.serializeUser((user, done)=>{  
    done(null, user.id);
});

passport.deserializeUser((id, done)=>{
    db.collection('login').findOne({id: id}, (error, result)=>{
        done(error, result);
    })
});