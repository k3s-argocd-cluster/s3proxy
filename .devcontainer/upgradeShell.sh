cd /tmp
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
sh -c "$(curl -fsSL https://ohmyposh.dev/install.sh)"

~/.local/bin/oh-my-posh font install meslo

git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
git clone https://github.com/MichaelAquilina/zsh-you-should-use.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/you-should-use
git clone https://github.com/fdellwing/zsh-bat.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-bat

sed -i 's/plugins\=\(git\)/plugins\=\(git kubectl zsh-autosuggestions you-should-use zsh-bat zsh-syntax-highlighting\)/g' ~/.zshrc

mkdir -p ~/.oh-my-zsh/themes/
cp /workspaces/s3proxy/.devcontainer/theme.omp.json ~/.oh-my-zsh/themes/custom.omp.json

echo "eval \"\$(~/.local/bin/oh-my-posh init zsh --config '/root/.oh-my-zsh/themes/custom.omp.json')\"" >> ~/.zshrc