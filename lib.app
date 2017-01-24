module elib/elib-authentication/lib

/****************
* This WebDSL e-lib contains a basic form of user registration.
* Its data model has a `User` and `UserAccountRequest` entity which can be extended.
* Email addresses are used as identifier for a user account. 
* After registration, a confirmation link is emailed. After the reg has been confirmed,
* a User entity is created.
* 
* The following functions need to be defined in your application code:

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
*
******************/


entity User{
  emailAddresses : Set<UserEmailAddress> (inverse=user, validate(emailAddresses.length > 0, "A user account should at least have one email address"))
  email : Email := emailAddresses.first.email
  username : String (name, id, validate(username.trim().length() > 4, "User name should be larger that 4 characters"))
  password : Secret

  function changePassword(password : Secret) {
    validate(password.length() > 5, "Password should have at least 6 characters.");
    this.password := password.digest();
  }
  function newPassword() : NewPassword {
    var n := NewPassword{ user := this };
    n.save();
    return n;
  }

}

entity UserEmailAddress{
  email : Email (id)
  user  : User
}

entity UserAccountRequest{
  email : Email
  username : String (validate( user!=null || username.trim().length() > 4, "User name should be larger that 4 characters"))
  password : Secret
  user : User
  requestIP : String
  type : String
  consumed : Bool (default=false)
  
  function sendEmail(){
    email registrationEmail(this);
  }
  
  function hasExpired() : Bool{
    var expireMoment := created.addHours( USER_REG_EXPIRATION_HOURS() );
    return consumed || now().after( expireMoment );
  }
  
  function confirmAccount(email : Email){
    var normalizedEmail := normalizeEmail(email);
    validate(!hasExpired(), "This account confirmation has expired. Please re-register" );
    if(normalizedEmail == normalizeEmail(this.email)){
      user := User{
        username := username
        password := password 
      };
      var eml := UserEmailAddress{
        email := normalizedEmail
      };
      user.emailAddresses.add(eml);
      consumed := true;
      user.save();
    }
    
  }
  
  function confirmNewEmail(){
    validate(!hasExpired(), "This account confirmation has expired. Please re-register" );
    var newEmail := UserEmailAddress{
      email := this.email
    };
    user.emailAddresses.add( newEmail );
    consumed := true;
  }
  
  function hasUniqueUsername() : Bool{
    var trimmed := username.trim();
    var regs := from UserAccountRequest where username = ~username.trim() and email != ~email;
    var activeRegs := [r | r : UserAccountRequest in regs where !r.hasExpired()];
    if(activeRegs.length > 0){
      return false;
    }else {
      var users := from User where username = ~username.trim();
      return users.length < 1;
    }
  }
  
  static function NEW_EMAIL() : String{
    return "NEW_EMAIL";
  }
  static function NEW_USER() : String{
    return "new_user_registration";
  } 
  function actionString() : String{
    if(type == UserAccountRequest.NEW_USER()){
      return "Confirm your registration";
    } else { if ( type == UserAccountRequest.NEW_EMAIL() ){
      return "Confirm your email address";
    } }
    return null;
  }
}

entity NewPassword {
  user -> User
  date :: DateTime  (default=now())
  used :: Bool
  function resetPassword(pw : Secret) {
    validate(valid(), "This request is no longer valid. A password reset link is only valid for " + RESET_PASS_EXPIRATION_HOURS() + " hours and can be used once.");
    validate(user != null, "Error: reset password: user is null");
    user.changePassword(pw);
    used := true;
  }
  
  function valid() : Bool{
    return !used && date.after( now().addHours(-1*RESET_PASS_EXPIRATION_HOURS()) );
  }
}

principal is User with credentials username, password

function getUser(e : Email) : User{
  var emailNormalized := normalizeEmail(e);
  var address := findUserEmailAddress(emailNormalized);
  return if(address != null) address.user else null;
}

function normalizeEmail( e : String) : Email{
  var normalized : String;
  normalized := e.trim();
  normalized := e.toLowerCase();
  return normalized;
}

section templates

template registerUserForm(){
  var registration := UserAccountRequest{ type:= UserAccountRequest.NEW_USER() }
  var password1 : Secret
  var password2 : Secret
  
  action register(){
    registration.password := password1.digest();
    var normalizedEmail := normalizeEmail(registration.email);
    var addresses := from UserEmailAddress where email = ~normalizedEmail;
    validate(addresses.length < 1, "A user with that email address already exists");
    registration.requestIP := remoteAddress();
    registration.save();
    registration.sendEmail();
  }
  
  form[all attributes]{
    fieldset("User name"){ input( registration.username ) validate( registration.hasUniqueUsername(), "This username is already taken" )}
    fieldset("Email address"){ input( registration.email ) }
    fieldset("Password: "){ input(password1){ validate(password1.length() > 5, "Password should at least have 6 characters") } } 
    fieldset("Repeat password: "){ input(password2) { validate(password1 == password2, "Passwords don't match.") } }
    
    fieldset(""){
      submit register(){"Register"}
    }

  }
}

define email registrationEmail(req : UserAccountRequest){
  to(req.email)
  subject("Complete Your Registration")
  from(FROM_EMAIL())
  
  h3{ "Complete Your Registration" }
  par { "We're almost there! In order to complete your registration on " output(HOMEPAGE_URL())
        ", you need to confirm your email address by clicking the following link."}
  par { navigate confirm-registration(req){ "activate your account" }}
  accountRequestEmailNote(req.requestIP)
}

define email passwordResetEmail(u : User, email : Email, n : NewPassword, remoteAddress : String) {
  to(email)
  from(FROM_EMAIL())
  subject("New password request")
  par{ "Dear " output(u.username) "," }
  par{ "This email is sent to you because a password-reset was requested for your account on " output(HOMEPAGE_URL()) "." }
  par{ "You can reset your password using the following link (expires in " output(RESET_PASS_EXPIRATION_HOURS()) " hours):" }
  par{ navigate reset-password(n){ "Reset password"} }
  accountRequestEmailNote(remoteAddress)
}

define email newEmailAddressEmail(req : UserAccountRequest){
  to(req.email)
  subject("Confirm your email address")
  from(FROM_EMAIL())
  
  h3{ "Confirm your email address" }
  par { "When clicking the link below, the email address " strong{ output(req.email) } " will be added to the user account with username " strong{ output(req.user.username) } " on " output(HOMEPAGE_URL()) "." }
  par { navigate confirm-registration(req){ "Confirm this email address." }}
  accountRequestEmailNote(req.requestIP)
}

template accountRequestEmailNote(reqIP : String){
  par{
    strong{ "Note: " } "In case you did not instantiate this request, you may ignore this email."
    " The request was sent from the following ip-address: " output(reqIP)
  }
}

template confirmRegistrationForm(reg : UserAccountRequest){
  var eml : Email
  
  action verifyReg(){
    reg.confirmAccount(eml);
    message("Your account is now confirmed and activated.");
    return url(HOMEPAGE_URL());
  }
  
  form[all attributes]{
    if( !reg.hasExpired() ){
      fieldset("Enter the email address you used to register"){
        input(eml)
      }
      fieldset(""){
        submit verifyReg(){ "Activate Your Account" }
      }
    } else{
      par{ "This registration has expired or is already confirmed. Please re-register or sign in."}
    }
  }
}

template changePasswordForm(u : User){
  var oldPass : Secret
  var newPass : Secret
  var newPass2: Secret
  
  action resetPass(){
    u.changePassword(newPass);
    message("Password changed successfully");
  }
  
  horizontalForm{
    fieldset("Old password"){input(oldPass)[placeholder="Your current password"]{ validate(u.password.check(oldPass), "Password does not match the current user password")}}
    fieldset("New password"){input(newPass)[placeholder="Your new password (should contain at least 6 characters)"]}
    fieldset("Repeat new password"){input(newPass2)[placeholder="Re-type your new password"]{validate(newPass == newPass2, "Passwords do not match")} }
    fieldset(""){
      submitlink resetPass()[class="btn btn-primary"]{ "Change password"}
    }
  }
}

template forgotPasswordForm(eml : Email){
  var email : Email := eml
  
  action newpassword() {
    var user := getUser(email);
    validate(user != null, "Sorry, could not find a user account with that email address.");
    if( user != null){
      for(e in user.emailAddresses){
        log("Sending password reset link to: " + e.email);
        email passwordResetEmail(user, e.email, user.newPassword(), remoteAddress());
      }
      message("A password reset link has been sent to the email addresses of the account you provided.");
    }
  }
          
  form[all attributes]{
    par{ "You can request a password reset by entering your email address" }
    
    fieldset("Email"){ input(email) }
    fieldset(""){
      submitlink newpassword()[class="btn btn-primary"]{"Request password-reset"}
    }
  }
}

template resetPasswordForm(n : NewPassword){
  var email : Email := ""
  var password1 : Secret
  var password2 : Secret
  action resetPass(){
    var foundUser := getUser(email);
    validate( foundUser == n.user, "Email address does not match the one from the user account, which is required for changing the password.");
    if(foundUser == n.user){
      n.resetPassword(password1);
      log("Password has been reset for account with email address: " +  email);
      message("Your password has been reset");
      return signin("" as URL);
    }
  }
  
  form[all attributes]{
    if(!n.valid()) {
      par{ "This request is no longer valid. A password reset link is only valid for " output(RESET_PASS_EXPIRATION_HOURS()) " hours and can be used once."  }
    } else{  
      fieldset("Enter your email"){ input(email) }
      fieldset("New password: "){ input(password1) } 
      fieldset("Repeat password: "){ input(password2) { validate(password1 == password2, "Passwords don't match.") } }
    
      fieldset(""){
        submitlink resetPass()[class="btn btn-primary"]{"Reset Password"}
      }
    }
  }  
}

template manageAccountForm(u : User){
  var newEmail : Email := ""
  
  action addEmail(){
    var emailNormalized := normalizeEmail(newEmail);
    var user := getUser(emailNormalized);
    validate(user == null, "The entered email address is already in use.");
    validate(emailNormalized != "" && emailNormalized.isValid(), "Please enter a valid email address");
    var changeRequest := UserAccountRequest{
      type := UserAccountRequest.NEW_EMAIL()
      user := u
      email := emailNormalized
      requestIP := remoteAddress()
    };
    changeRequest.save();
    email newEmailAddressEmail(changeRequest);
    message("A confirmation email has been sent to the provided email addres. Click the link in the confirmation email to add the email address to your account.");
  }
  
  action removeEmail(addr : UserEmailAddress){
    u.emailAddresses.remove(addr);
    if(u.emailAddresses.length > 0){
      message("The email address " + addr.email + " has been removed from your account");
    }
    addr.user := null;
    addr.delete();
  }
  
  form[all attributes]{
    fieldset("Username"){ output(u.username) }
    fieldset("Email addresses"){
      for(addr in u.emailAddresses order by addr.email){
        output(addr.email) " " confirmActionLink(""+addr.id, "Are you sure you want to remove this email address?"){ "remove" }
        submit removeEmail(addr)[id=""+addr.id, style="display:none;"]{}         
      }separated-by{ br }
    }
    fieldset("New Email Address"){
      "You can have multiple email addresses linked to your account. New email addresses need to be confirmed through a link sent to the new email address." br
      input(newEmail)[placeholder="New email address"] " " submit addEmail(){ "Add New Email" }
    }
  }
  
  changePasswordForm(u)[all attributes]
  
}

template confirmActionLink(actionid : String, confirmQuestion : String){
  <a href="javascript:var result = confirm(\"" + confirmQuestion + "\"); if(result){ document.getElementById(\"" + actionid + "\").click(); } else { void(0); }">
    elements
  </a>
}

template loginForm(from : URL){
  var mailAddress : Email
  var password : Secret
  var stayLoggedIn := false
  
  action signinAction() {
    getSessionManager().stayLoggedIn := stayLoggedIn;
    var u := getUser(mailAddress);
    validate(u != null && authenticate( normalizeEmail(u.username), password), "The login credentials are not valid.");
    message("You are now logged in.");
    if(from==""){
      return root();
    } else {
      return url(from); 
    }
  }

  form[all attributes]{
    fieldset("Email address"){ input(mailAddress) }
    fieldset("Password"){ input(password) }
    fieldset(""){ input(stayLoggedIn) " Stay logged-in"}
    fieldset(""){
      submitlink signinAction()[class="btn btn-primary"]{ "Login" } " "
      submitlink action{ goto forgot-password(mailAddress);}[class="btn btn-warning"]{"Forgot password"}
    }
  }
}

template signOffLink(){
  var returnUrl : URL :=  url(navigate( root() ))
  action signoutuser(){
    securityContext.principal := null;
    return url(returnUrl);
  }
  submitlink signoutuser()[ignore default class] { "Sign Off" }
}

template userAccountRequestForm(req : UserAccountRequest){
  if(req.type == UserAccountRequest.NEW_EMAIL()){
    confirmNewEmailForm(req)[all attributes]
  } else if(req.type == UserAccountRequest.NEW_USER()){
    confirmRegistrationForm(req)[all attributes]
  }
}

template confirmNewEmailForm(req : UserAccountRequest){
  var expired := req.hasExpired()
  init{
    if(!expired){
      req.confirmNewEmail();
    }
  }
  if(!expired){
    "Your new email address is now confirmed and has been added to your account."
  }
}



/* * * * * * * * * * * * * * * * * * */
// The following pages will work, but are solely for illustration of the usage.
// You need to override these pages in order to present the in the style of the app.
access control rules

rule page confirm-registration(reg : UserAccountRequest){ true }
rule page signup(){ true }
rule page forgot-password(eml : Email){ true }
rule page reset-password(n : NewPassword){ true }
rule page signin(from : URL){ true }
rule page manage-account(u : User){ loggedIn() && securityContext.principal == u }

section pages

page signin(from : URL) {
  title{ "Sign In" }
  h2{ "Sign in" }
  
  loginForm(from)[class="form-horizontal"]
}

page confirm-registration(reg : UserAccountRequest){
  title{ output(reg.actionString()) }  
  h2{ output(reg.actionString()) }
  
  userAccountRequestForm(reg)[class="form-horizontal"]
}

page signup(){
  title{ "User Registration" }
  h2{ "Register" }
  
  registerUserForm[class="form-horizontal"]
}

page forgot-password(eml : Email){
  title{ "Forgot password" }
  h2{ "Forgot password" }
  
  forgotPasswordForm(eml)[class="form-horizontal"]
}

page reset-password(n : NewPassword) {
  title{ "Reset password" }
  h2{ "Reset password for user account: " output(n.user.username) }

  resetPasswordForm(n)[class="form-horizontal"]
}

page manage-account(u : User){
  title{ "Manage Account" }
  h2{ "Manage Account - " output(u.username) }
  
  manageAccountForm(u)[class="form-horizontal"]
}

/* * * * * * * * * * * * * * * * * * */