server {
    name           = "psyrcd-dev"
    domain         = "irc.psybernetics.org"
    description    = "I fought the lol, and. The lol won."
    welcome        = "Welcome to {}" // Formatted with server["name"].
    link_key       = "${PSYRCD_LINK_KEY}" // Populated from the environment.
    ping_frequency = 120 

    max {
        clients    = 8192
        idle_time  = 300 
        nicklen    = 12  
        channels   = 200 
        topiclen   = 512 
    }
}

oper {
    /* Set the username to a false value to disable the oper system.
     * Set the password to true to generate a random password, false to disable
     * the oper system, a string of your choice or pipe at runtime:
     * $ openssl rand -base64 32 | psyrcd --preload -f
     */
    username = true
    password = true  
}
services {
    nickserv {
        enabled = false
        database_uri = "sqlite:///var/opt/psyrcd/nickserv.db"
    }
    chanserv {
        enabled = false
        database_uri = "sqlite:////var/opt/psyrcd/chanserv.db"
    }
}
