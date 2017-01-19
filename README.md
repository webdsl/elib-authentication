# elib-authentication
A WebDSL Elib for user authentication with support for user registration, password reset, multiple email addresses and login

This WebDSL e-lib contains a basic form of user registration.
Its data model has a `User` and `UserAccountRequest` entity which can be extended.
Email addresses are used as identifier for a user account. 
After registration, a confirmation link is emailed. After the reg has been confirmed,
a User entity is created.
 
The following functions need to be defined in your application code:

```
function HOMEPAGE_URL() : URL{
  return "your_application_url_here";
}

function FROM_EMAIL() : Email{
  return "your@email.here";
}

//the time in hours for which a registration confimration link stays valid
function USER_REG_EXPIRATION_HOURS() : Int{
  return 48;
}
```
