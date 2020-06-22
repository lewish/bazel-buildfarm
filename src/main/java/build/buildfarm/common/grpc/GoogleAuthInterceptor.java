// Copyright 2017 The Bazel Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package build.buildfarm.common.grpc;

import build.buildfarm.v1test.GoogleAuthConfig;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudresourcemanager.CloudResourceManager;
import com.google.api.services.cloudresourcemanager.model.TestIamPermissionsRequest;
import com.google.api.services.cloudresourcemanager.model.TestIamPermissionsResponse;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import io.grpc.*;
import io.grpc.ServerCall.Listener;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/**
 * Utility functions to handle Metadata for remote Grpc calls.
 */

public class GoogleAuthInterceptor implements ServerInterceptor {

    public static final int AUTH_VALID_DURATION = 60 * 1000;

    private static final Map<String, Long> accessTokenValidToMillis = new ConcurrentHashMap<>();

    private final GoogleAuthConfig config;

    public GoogleAuthInterceptor(GoogleAuthConfig config) {
        this.config = config;
    }

    @Override
    public <ReqT, RespT> Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        if (this.config == null || this.config.getProjectId() == null || this.config.getProjectId() == "") {
            return next.startCall(call, headers);
        }

        GoogleCredentials credentials = headers.get(Metadata.Key.of("authorization", new GoogleAuthInterceptor.AuthorizationHeaderMarshaller()));
        String accessToken = credentials.getAccessToken().getTokenValue();

        if (accessTokenValidToMillis.containsKey(accessToken) && accessTokenValidToMillis.get(accessToken) > Clock.systemUTC().millis()) {
            // Allow cached auth access.
            return next.startCall(call, headers);
        }

        if (credentials == null) {
            throw new StatusRuntimeException(Status.FAILED_PRECONDITION);
        }

        CloudResourceManager service = null;
        try {
            service = createCloudResourceManagerService(credentials);
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        TestIamPermissionsRequest requestBody =
                new TestIamPermissionsRequest().setPermissions(this.config.getRequiredPermissionsList());
        try {
            TestIamPermissionsResponse testIamPermissionsResponse =
                    service.projects().testIamPermissions(this.config.getProjectId(), requestBody).execute();
            if (testIamPermissionsResponse.getPermissions() == null) {
                throw new RuntimeException("User does not have required permissions: " + this.config.getRequiredPermissionsList());
            }
            for (String requiredPermission : this.config.getRequiredPermissionsList()) {
                if (!testIamPermissionsResponse.getPermissions().contains(requiredPermission)) {
                    throw new StatusRuntimeException(Status.UNAUTHENTICATED);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // If that all worked, cache the access lookup for some time.
        accessTokenValidToMillis.put(accessToken, Clock.systemUTC().millis() + AUTH_VALID_DURATION);
        return next.startCall(call, headers);
    }

    public static class AuthorizationHeaderMarshaller implements Metadata.AsciiMarshaller<GoogleCredentials> {

        @Override
        public String toAsciiString(GoogleCredentials googleCredentials) {
            return googleCredentials.getAccessToken().getTokenValue();
        }

        @Override
        public GoogleCredentials parseAsciiString(String s) {
            if (!s.toLowerCase().startsWith("bearer ")) {
                throw new RuntimeException("Authorization header is not in the expected format.");
            }
            return GoogleCredentials.create(new AccessToken(s.substring(7), null));
        }
    }

    public static CloudResourceManager createCloudResourceManagerService(GoogleCredentials credential)
            throws IOException, GeneralSecurityException {
        CloudResourceManager service =
                new CloudResourceManager.Builder(
                        GoogleNetHttpTransport.newTrustedTransport(),
                        JacksonFactory.getDefaultInstance(),
                        new HttpCredentialsAdapter(credential))
                        .setApplicationName("bazel-buildfarm-server")
                        .build();
        return service;
    }
}
