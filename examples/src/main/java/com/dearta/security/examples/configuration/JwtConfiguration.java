package com.dearta.security.examples.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;
import org.hibernate.validator.constraints.NotEmpty;


/**
 * Created by sepp on 26.09.15.
 */
public class JwtConfiguration extends Configuration {

    @NotEmpty
    private String key;


    @JsonProperty
    public String getKey() {
        return this.key;
    }

    @JsonProperty
    public void setKey(String key) {
        this.key = key;
    }

}
