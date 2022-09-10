import os
from functools import wraps

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

# initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# initialize gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# create database connection
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    """Class used to represent the User data in the database."""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    """Class used to represent the Posts in the database."""
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    """Class used to represent the Comments table in the database."""
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    comment_author = relationship("User", back_populates="comments")
    parent_post = relationship("BlogPost", back_populates="comments")


# create the database - ONLY NEEDED ONCE
db.create_all()


def admin_only(function):
    """Decorator used to check the current user before redirecting to sensitive pages."""
    @wraps(function)
    def inner_function(*args, **kwargs):
        # check if a user is logged in
        if current_user.is_authenticated:
            # check if the user is the admin
            if current_user.id == 1:
                # proceed with loading the page
                return function(*args, **kwargs)
        # not an admin, abort the loading of the page
        return abort(403)
    return inner_function


@login_manager.user_loader
def load_user(user_id):
    """Return the current user."""
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    """Render the home page."""
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Render the register page."""
    form = RegisterForm()

    if form.validate_on_submit():
        # POST method - register the user into the database

        # create new user data
        new_user = User()
        new_user.email = form.email.data
        new_user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user.name = form.name.data

        # check if the user already exists and redirect to the login page in that case
        if User.query.filter_by(email=new_user.email).first():
            flash("You've already signed up with that email, sign in instead!")
            return redirect(url_for("login"))

        # save new user to the database
        db.session.add(new_user)
        db.session.commit()

        # login the user after successful registration
        login_user(new_user)

        # return to the home page
        return redirect(url_for('get_all_posts'))

    # GET method - render the register page
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Render the login page."""
    form = LoginForm()

    if form.validate_on_submit():
        # POST method - proceed login checks
        user = User.query.filter_by(email=form.email.data).first()

        # login in case the user is found and the password is correct
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        elif not user:
            # email not found
            flash("The email you entered does not exist, please try again!")
        else:
            # incorrect password
            flash("Password incorrect. Please try again.")

    # GET method - render the login page
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    """Render the logout page."""
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    """Render the page with the selected post content."""
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()

    if form.validate_on_submit():
        # POST request - save the comment
        if current_user.is_authenticated:
            # user is logged in, comment can be saved
            new_comment = Comment(
                text=form.comment_text.data,
                comment_author=current_user,
                parent_post=BlogPost.query.get(post_id)
            )
            db.session.add(new_comment)
            db.session.commit()
        else:
            # user is not logged in, redirect to the login page
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
    # GET request - render the post page
    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


@app.route("/about")
def about():
    """Render the about page."""
    return render_template("about.html")


@app.route("/contact")
def contact():
    """Render the contact page."""
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    """Render the create post page."""
    form = CreatePostForm()
    if form.validate_on_submit():
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
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    """Render the edit post page."""
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    """Handle delete post request."""
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # execute the server
    app.run()
