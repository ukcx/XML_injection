#Run flask without pipenv
pip install flask flask-sqlalchemy flask-marshmallow marshmallow-sqlalchemy dicttoxml lxml
python db_create.py (if db.sqlite does not exist)
python app.py

#Run flask with pipenv
pip install pipenv
pipenv shell
pipenv install
python db_create.py (if db.sqlite does not exist)
python app.py