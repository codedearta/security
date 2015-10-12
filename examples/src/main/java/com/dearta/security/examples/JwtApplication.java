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
import org.eclipse.jetty.servlets.CrossOriginFilter;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import java.util.EnumSet;

/**
 * Created by sepp on 26.09.15.
 */
public class JwtApplication extends Application<JwtConfiguration> {

    public static void main(String[] args) throws Exception {
        new JwtApplication().run(args);
    }

    public String getName() {
        return "Jwt Application";
    }

    public void initialize(Bootstrap<JwtConfiguration> bootstrap) {
        bootstrap.addBundle(new AssetsBundle("/assets/", "/"));
    }

    public void run(JwtConfiguration configuration, Environment environment) {
        // Enable CORS headers
        final FilterRegistration.Dynamic cors =
                environment.servlets().addFilter("CORS", CrossOriginFilter.class);

        // Configure CORS parameters
        cors.setInitParameter("allowedOrigins", "*");
        cors.setInitParameter("allowedHeaders", "X-Requested-With,Content-Type,Accept,Origin");
        cors.setInitParameter("allowedMethods", "OPTIONS,GET,PUT,POST,DELETE,HEAD");

        // Add URL mapping
        cors.addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), true, "/*");

        environment.jersey().register(AuthFactory.binder(new JwtAuthenticatorFactory<User>(new JwtAuthenticator(configuration.getKey()),
                this.getName(),
                User.class)));

        environment.jersey().setUrlPattern("/api/*");
        environment.jersey().register(new AuthResource(configuration));
    }
}
