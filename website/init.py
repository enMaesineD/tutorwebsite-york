from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from .models import Subjects
from werkzeug.security import generate_password_hash, check_password_hash
from.import db
from flask_login import login_user, login_required, logout_user, current_user
from .util import Utils

init = Blueprint('init', __name__)
@init.route('/init', methods=['GET','POST'])
def init():
    if request.method == 'POST':
        new_subject = Subjects(name="math", status=1)
        db.session.add(new_subject)

        new_subject = Subjects(name="english", status=1)
        db.session.add(new_subject)

        new_subject = Subjects(name="science", status=1)
        db.session.add(new_subject)

        new_subject = Subjects(name="french", status=1)
        db.session.add(new_subject)

        new_subject = Subjects(name="humanities", status=1)
        db.session.add(new_subject)

        db.commit()


    return render_template("login.html", user=current_user)
