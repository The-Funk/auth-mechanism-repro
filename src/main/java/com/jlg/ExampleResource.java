package com.jlg;

import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/hello")
public class ExampleResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String hello() {
        return "Hello from RESTEasy Reactive";
    }

    @GET
    @Path("/roles")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("ROLE1")
    public String helloWithRoles() {
        return "Hello with roles!";
    }

}
