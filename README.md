# King Family Recipes
 
Web recipe catalog built with Flask, and authentication provided by Google Oauth to enable users to submit and edit their own recipes.
 
## Instructions
 
Install Vagrant Vitual Machine
In your terminal/shell cd vagrant and run vagrant up and vagrant ssh
cd to vagrant/catalog and run project.py
Website should be accessed at localhost:5000
 
## JSON endpoints
 
Category JSON: /category/<int:category_id>/recipes/JSON
Recipe JSON: /category/<int:category_id>/recipes/<int:recipe_id>/JSON