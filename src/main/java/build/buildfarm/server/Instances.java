// Copyright 2018 The Bazel Authors. All rights reserved.
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

package build.buildfarm.server;

import build.buildfarm.instance.Instance;

public interface Instances {
  void start(String publicName);

  void stop() throws InterruptedException;

  Instance getFromBlob(String blobName) throws InstanceNotFoundException;

  Instance getFromUploadBlob(String uploadBlobName) throws InstanceNotFoundException;

  Instance getFromOperationsCollectionName(String operationsCollectionName)
      throws InstanceNotFoundException;

  Instance getFromOperationName(String operationName) throws InstanceNotFoundException;

  Instance getFromOperationStream(String operationStream) throws InstanceNotFoundException;

  Instance get(String name) throws InstanceNotFoundException;

  static Instances singular(Instance instance) {
    return new Instances() {
      @Override
      public Instance getFromBlob(String blobName) throws InstanceNotFoundException {
        return instance;
      }

      @Override
      public Instance getFromUploadBlob(String uploadBlobName) throws InstanceNotFoundException {
        return instance;
      }

      @Override
      public Instance getFromOperationsCollectionName(String operationsCollectionName)
          throws InstanceNotFoundException {
        return instance;
      }

      @Override
      public Instance getFromOperationName(String operationName) throws InstanceNotFoundException {
        return instance;
      }

      @Override
      public Instance getFromOperationStream(String operationStream)
          throws InstanceNotFoundException {
        return instance;
      }

      @Override
      public Instance get(String name) throws InstanceNotFoundException {
        return instance;
      }

      @Override
      public void start(String publicName) {}

      @Override
      public void stop() {}
    };
  }
}
