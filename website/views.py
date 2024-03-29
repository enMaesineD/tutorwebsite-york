from flask import Blueprint, render_template, flash, request, jsonify
from flask_login import login_required, current_user
from .models import User, Pairs, Hours
from . import db
from sqlalchemy.orm import aliased
from datetime import datetime
from .util import Utils

views = Blueprint('views', __name__)


@views.route('/', methods=['GET', 'POST']) # homepage
@login_required
def home(tutor_id=None):
    tutors = User.query.filter_by(role=2).all()
    tutees = User.query.filter_by(role=1).all()

    UserTutor = aliased(User)
    UserTutee = aliased(User)

    # pairs_list = (Pairs.query.join(User, User.id == Pairs.tutor_id)
    #         .join(User, User.id == Pairs.tutee_id)
    #          .add_columns(Pairs.tutor_id, User.first_name, User.last_name, Pairs.tutee_id, User.first_name, User.last_name)).all()

    pairs_list = (Pairs.query
                  .join(UserTutor, UserTutor.id == Pairs.tutor_id)
                  .join(UserTutee, UserTutee.id == Pairs.tutee_id)
                  .add_columns(
        Pairs.tutor_id,
        UserTutor.first_name.label("tutor_first_name"),
        UserTutor.last_name.label("tutor_last_name"),
        Pairs.tutee_id,
        Pairs.id,
        UserTutee.first_name.label("tutee_first_name"),
        UserTutee.last_name.label("tutee_last_name")
    ).all())

    unpairs_list = (Pairs.query.filter_by(tutor_id=0)
                  .join(UserTutee, UserTutee.id == Pairs.tutee_id)
                  .add_columns(
        Pairs.id,
        Pairs.subject,
        UserTutee.email.label("tutee_email"),
        UserTutee.first_name.label("tutee_first_name"),
        UserTutee.last_name.label("tutee_last_name"),
        UserTutee.grade.label("tutee_grade"),
    ).all())

    print("Unpaired: ")
    print(unpairs_list)

    print(pairs_list)

    print(tutors)
    if request.method == 'GET':
        print("Get request on home page.")
        print(len(tutors))
        return render_template("home.html", user=current_user, tutors=tutors, tutees=tutees, pairs_list=pairs_list, unpairs_list=unpairs_list)

@views.route('/unpair', methods=['POST'])
def unpair():
    data = request.get_json()
    data_id = data['Id']
    pair = Pairs.query.get(data_id)
    if pair:
        pair.tutor_id = 0
        db.session.commit()

        tutors = User.query.filter_by(id=pair.tutor_id).all()
        tutees = User.query.filter_by(id=pair.tutee_id).all()

        u = Utils()
        u.send_mail(tutors[0].email,
                    'Branksome Hall Tutor Club',
                    'This email is to inform you that you are no longer paired up with tutee: ' + tutors[0].first_name + ' ' +
                    tutors[0].last_name + '.' + 'Please wait until you are paired up with another student.')
        u.send_mail(tutees[0].email,
                    'Branksome Hall Tutor Club',
                    'This email is to inform you that you are no longer paired up with tutor: ' + tutees[0].first_name + ' ' +
                    tutees[0].last_name + '.' + 'If you would still like tutoring in this subject, please let Ms. Contreras and Ms. Blyth know.')

        return jsonify({"message": "Unpaired successfully"}), 200
    else:
        return jsonify({"error": "Invalid data"}), 400


@views.route('/hours', methods=['GET', 'POST'])
@login_required
def hours():
    # Fetch and display time entries
    times = Hours.query.filter_by(tutor_id=current_user.id).all()

    if request.method == 'POST':
        selected_time = int(request.form.get('selected_time'))
        note = request.form.get('notes')
        # Calculate the hours based on the selected time
        hours_logged = selected_time

        new_hour = Hours(hours=hours_logged, note=note, tutor_id=current_user.id, time=datetime.utcnow())
        db.session.add(new_hour)
        db.session.commit()
        flash('Hours logged!', category='success')

    return render_template("hours.html", user=current_user, times=times)

@views.route('/delete_time/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_time(id):
    # Implement logic to delete the time entry with the specified ID
    time_entry = Hours.query.get(id)
    if time_entry:
        db.session.delete(time_entry)
        db.session.commit()
        flash('Time entry deleted!', category='success')
    else:
        flash('Time entry not found.', category='danger')

    # Render the 'hours.html' template after deletion
    return render_template('hours.html', user=current_user, times=Hours.query.filter_by(tutor_id=current_user.id).all())

@views.route('/tutee_page', methods=['GET','POST'])
@login_required
def tutee_page():
    return render_template("tutee_page.html", user=current_user)