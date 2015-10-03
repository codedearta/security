package com.dearta.security.examples;

import com.dearta.security.dropwizard.JwtAuthenticator;
import com.dearta.security.dropwizard.JwtAuthenticatorFactory;
import com.dearta.security.dropwizard.User;
import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.auth.AuthFactory;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import com.dearta.security.examples.configuration.JwtConfiguration;
import com.dearta.security.examples.resources.AuthResource;

/**
 * Created by sepp on 26.09.15.
 */
public class JwtApplication extends Application<JwtConfiguration> {

    public static void main(String[] args) throws Exception {
        new JwtApplication().run(args);
    }

    @Override
    public String getName() {
        return "Jwt Application";
    }

    @Override
    public void initialize(Bootstrap<JwtConfiguration> bootstrap) {
        bootstrap.addBundle(new AssetsBundle());
    }

    @Override
    public void run(JwtConfiguration configuration, Environment environment) {
        environment.jersey().register(AuthFactory.binder(new JwtAuthenticatorFactory<User>(new JwtAuthenticator(configuration.getKey()),
                this.getName(),
                User.class)));

        environment.jersey().setUrlPattern("/api/*");
        environment.jersey().register(new AuthResource(configuration));
    }
}
