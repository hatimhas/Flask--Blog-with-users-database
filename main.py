from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

ckeditor = CKEditor(app)
Bootstrap(app)
login_manage = LoginManager()
login_manage.init_app(app)
db = SQLAlchemy(app)


# Configure Gravatar
gravatar = Gravatar(
    app,
    size=100,          # Default size for avatars
    rating='g',        # Default rating
    default='retro',   # Default image when no gravatar is available
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)

# CONFIGURE TABLES
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    
    # One-to-Many relationship with BlogPost
    posts = db.relationship("BlogPost", back_populates="author")
    
    # One-to-Many relationship with Comment
    comments = db.relationship("Comment",back_populates="comment_author",cascade="all, delete")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    
    # Foreign key to link to User table
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = db.relationship("Users", back_populates="posts")
    
    comments = relationship("Comment", back_populates="parent_post")
    
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    
    # Corrected Foreign Key to link to the Users table
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    
    # Relationship to refer back to the User
    comment_author = db.relationship("Users", back_populates="comments")
    
    # Foreign key to link to BlogPost table
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    
    # Relationship to refer back to the BlogPost
    parent_post = db.relationship("BlogPost", back_populates="comments")

    
     
db.create_all()


@login_manage.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#Dec func admin onlu
def admin_only(f):
    @wraps(f)
    def dec_function(*args,**kwargs):
        if not current_user.is_authenticated and current_user.id !=1:
            abort(403)
        else:
            return f(*args,**kwargs)
    return dec_function

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    user_id = current_user.id if current_user.is_authenticated else None    
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user_id=(user_id))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256',  salt_length=8)
        new_user = Users(
            name=form.name.data,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print("Form validated successfully")  # Debugging info
        user = Users.query.filter_by(email=form.email.data).first()
        
        if not user:
            print("No user found")  # Debugging info
            flash('This email does not exist. Please try again or register.', 'warning')
            return redirect(url_for('login'))
        else:
            if check_password_hash(user.password, form.password.data):
                print("Password correct")
                login_user(user)
                return (redirect(url_for('get_all_posts')))
            else:
                print("Password Incorrect")
                flash('Incorrect password. Please try again.', 'danger')
                return redirect(url_for('login'))
    print("Form did not validate")  # Debugging info
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    
    return render_template("post.html", post=requested_post, current_user=current_user, form=form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        print("validated")
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        print("commited")
        return redirect(url_for("get_all_posts"))
    print("NOt validated")
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author=current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))  # Default to port 5000 if PORT is not set
    app.run(host='0.0.0.0', port=port, debug=True)
