require 'unix_crypt'

DEFAULT_PASSWORD_LIST_PATH = '500-worst-passwords.txt'
DEFAULT_PASSWD_PATH = 'passwd.txt'
DEFAULT_SHADOW_PATH = 'shadow.txt'
DEFAULT_OUTPUT_PATH = 'out.txt'

def parse_args 
  if ARGV.empty? || ARGV.any? { |arg| ['--help', '-h'].include? arg }
    puts <<-HELP
================================================================
 PWDCRCKR 
================================================================
 SYNOPSIS
     ruby pwdcrckr.rb [-h] [-d] [-pl file] [-p file] [-s file] 
        [-o file]

 OPTIONS
     -h, --help                      Print this help
     -d, --default                   Use default files
     -pl [file]                      Specify password list file
     -p [file]                       Specify passwd file
     -s [file]                       Specify shadow file
     -o [file]                       Specify output file
================================================================
    HELP
    abort
  elsif ARGV.any? { |arg| ['--defaults', '-d'].include? arg }
    {}
  else
    option_values = []
    ARGV.each_slice(2) do |option, value|
      options = ['-pl', '-p', '-s', '-o']
      option_values[options.index option] = value
    end
    {
      password_list_path: option_values[0],
      passwd_path: option_values[1],
      shadow_path: option_values[2],
      output_path: option_values[3],
    }
  end
end

def read_file(path)
  resp = []
  puts "Reading from #{path}..."
  IO.foreach(path) { |line|
    resp << line.strip
  }
  resp
end

def get_uid(username_query, passwd)
  passwd.each { |line|
    line = line.split ':'
    username = line[0]
    uid = line[2]
    return uid.to_i if username == username_query
  }
end

def get_users(shadow, passwd)
  shadow.map { |line|
    line = line.split ':'
    username = line[0]
    hashed_password = line[1]
    has_valid_password = !(['*', '!'].include? hashed_password)
    uid_is_over_1000 = (get_uid username, passwd) > 1000
    if has_valid_password && uid_is_over_1000
      {
        username: username,
        hashed_password: hashed_password,
      }
    else
      nil
    end
  }.compact
end

def crack(user, password_list)
  start = Time.now
  puts "Cracking user #{user[:username]}..."
  password_list.each { |password|
    if UnixCrypt.valid? password, user[:hashed_password]
      user[:password] = password
      user[:crack_time] = "#{Time.now - start}s"
      puts "Found password #{user[:password]} in #{user[:crack_time]}!"
      return user
    end
  }
  puts 'Could not find password for this user.'
  user
end

def parse_results(results)
  resp = "Password cracker results:\n"
  results.each { |result|
    resp += "===\n"
    resp += "Username: #{result[:username]}\n"
    resp += "Password: #{result[:password] || 'Unable to crack.'}\n"
    resp += "Time to crack: #{result[:crack_time] || 'Unable to crack.'}\n"
  }
  resp
end

def write_file(results, filename)
  filename ||= DEFAULT_OUTPUT_PATH
  IO.write filename, results
  puts "Wrote results to #{filename}."
end

args = parse_args

password_list = read_file args[:password_list_path] || DEFAULT_PASSWORD_LIST_PATH
passwd = read_file args[:passwd_path] || DEFAULT_PASSWD_PATH
shadow = read_file args[:shadow_path] || DEFAULT_SHADOW_PATH

users = get_users shadow, passwd

results = users.map { |user|
  crack user, password_list
}
write_file parse_results(results), args[:output_path]
