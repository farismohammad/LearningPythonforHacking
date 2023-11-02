import smtplib, subprocess

def send_mail(email, passwd, message):
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email, passwd)
    server.sendmail(email, email, message) #(from:email, to:email, message)
    server.quit()

command = "echo it works" #any system command
result = subprocess.Popen(command, shell=True)
send_mail("email", "passwd", result)