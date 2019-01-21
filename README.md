# Item Catalog
---------------
* Udacity Item Catalog Project
* This app was written In Python 2.7.

Prerequisites
-------------
* Python 2.7.x
* Vagrant
* VirtualBox


Instructions
------------
1. Clone or download the vagrant enviroment from [Udacity](https://github.com/udacity/fullstack-nanodegree-vm.git) 
2. Clone this repo and place in the VM at `/vagrant/catalog`.
3. Run command `vagrant up` while targeting the vagrant folder of the repo in step 1.
4. Once the VM is running, execute command `vagrant ssh`
5. Run command `cd /vagrant` to enter the shared vagrant folder while logged into the VM
6. Install pipenv with `sudo pip install pipenv`
7. Install dependencies with `pipenv install`
8. Start app by running `python /vagrant/catalog/app.py`
9. Navigate to `http://localhost:5000` in a web browser to access the app
10. To modify any data you must signin using either your Google Plus accout or Facebook
11. To Edit data using the front-end, navigate to `Categories` or `Food` using the navigation menu

Endpoints
-------------
**Categories**
----
* **URL**
  /api/v1/categories

    * **Available Methods**
    `GET`, `POST`

    * **HTML Form Params**
    **Required for POST:**
    `category=[string]`

* **URL**
   /api/v1/categories/<id>

    * **Available Methods**
    `PUT`, `DELETE`

    * **HTML Form Params**
    **For PUT:**
    `update-category=[string]`

**Food**
----
* **URL**
  /api/v1/food

    * **Available Methods**
    `GET`, `POST`

    * **HTML Form Params**
    **Required for POST:**
    `insert-name=[string]`
    `insert-category=[int]`

    **Optional for POST:**
    `insert-description=[string]`

* **URL**
   /api/v1/categories/<id>

    * **Available Methods**
    `PUT`, `DELETE`

    * **HTML Form Params**
    **For PUT:**
    `insert-name=[string]`
    `insert-category=[int]`
    `insert-description=[string]`

* **URL**
   /api/v1/categories/food

    * **Available Methods**
    `GET`

    * **Response**
    JSON object of food items per category


Credit
------
Credit goes to the Udacity Full Stack nanodegree program