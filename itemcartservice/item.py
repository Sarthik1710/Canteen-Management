from pymongo import MongoClient
from flask import Flask,jsonify
import json
import requests
from bson import json_util
from flask_restful import Api, Resource, reqparse, request

app = Flask(__name__)
api = Api(app)


mongo_uri = "mongodb://mongodb:27017/"
database_name = "MAP"

# Connect to MongoDB Atlas
client = MongoClient(mongo_uri)

# Access the specified database and collection
database = client[database_name]
collection_item = database["items"]
collection_order = database["orders"]


def checkLogin(email, token):
    api_url = "http://auth:3003/auth/isLoggedIn"
    # Set the data you want to send in the POST request
    post_data = {
        "email": email
    }
    headers = {
        "x-access-token": token
    }

    response = requests.post(api_url, json=post_data, headers=headers)
    response = response.json()

    if response["auth"] == True:
        return True
    else:
        return False
    
class getMenu(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email")
        args = parser.parse_args()

        email = args["email"]
        token = request.headers.get('x-access-token')

        if checkLogin(email,token):
        # if True:
            cursor = collection_item.find({})
            return json.loads(json_util.dumps(cursor)), 200
        else:
            return "Invalid"


class addItemtoCart(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("id")
        parser.add_argument("email")
        parser.add_argument("count")
        args = parser.parse_args()

        email = args["email"]
        id = int(args["id"])
        token = request.headers.get('x-access-token')

        if checkLogin(email,token):
        # if True:
            cursor = collection_item.find_one({"id":id})
            cursor = json.loads(json_util.dumps(cursor))
            print(cursor)
            collection_order.insert_one({
                "email": email,
                "id":id,
                "name":cursor["name"],
                "count":int(args["count"]),
                "price":cursor["price"]
            })
            return "Item Added",200
        else:
            return "Invalid"


class removeItemfromCart(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email")
        parser.add_argument("id")
        args = parser.parse_args()

        email = args["email"]
        id = int(args["id"])
        token = request.headers.get('x-access-token')

        if checkLogin(email,token):
        # if True:
            collection_order.delete_one({"id":id,"email":email})
            return "Item Removed",200
        else:
            return "Invalid"

class updateIteminCart(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("id")
        parser.add_argument("email")
        parser.add_argument("count")
        args = parser.parse_args()

        email = args["email"]
        id = int(args["id"])
        token = request.headers.get('x-access-token')

        if checkLogin(email,token):
        # if True:
            collection_order.update_one({"id":id, "email":email}, {'$set': {"count":int(args["count"])}})
            return "Item Updated",200
        else:
            return "Invalid"
    

class getCartItems(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("email")
        args = parser.parse_args()

        email = args["email"]
        token = request.headers.get('x-access-token')

        if checkLogin(email,token):
        # if True:
            cursor = collection_order.find({"email":email})
            cursor = json.loads(json_util.dumps(cursor))
            return cursor,200
        else:
            return "Invalid"

api.add_resource(getMenu, '/item')
api.add_resource(addItemtoCart,'/item/addItem')
api.add_resource(removeItemfromCart, '/item/removeItem')
api.add_resource(updateIteminCart, '/item/updateItem')
api.add_resource(getCartItems, '/item/getCartItems')
app.run(host ='0.0.0.0', port = 3001, debug=True)