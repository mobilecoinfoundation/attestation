FROM ubuntu:22.04

# Note: this installs zsh and oh-my-zsh and sets them as the default shell for
# the user. This is more or less subjective which shell to use and zsh seemed
# like a safe bet.
# Since this dockerfile is only used for development and not deployment it
# seemed reasonable to install these niceties for developers.
RUN  apt-get update \
  && apt-get install -y \
     build-essential curl git wget libclang-14-dev cmake sudo zsh \
  && apt-get clean \
  && rm -r /var/lib/apt/lists

# We create a user for the container. The name will be `docker`
ARG USERNAME=docker
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
  && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
  && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
  && chmod 0440 /etc/sudoers.d/$USERNAME \
  && chsh -s /usr/bin/zsh $USERNAME

USER $USERNAME

# install oh-my-zsh
RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y