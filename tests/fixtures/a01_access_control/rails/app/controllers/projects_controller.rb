class ProjectsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:destroy] # codit-expect: CWE-862 authentication skipped on the destructive destroy action

  def index
    @projects = current_user.projects.order(updated_at: :desc)
  end

  def show
    @project = Project.find(params[:id]) # codit-expect: CWE-639 any project by id, not scoped to current_user and no Pundit authorize
    @members = @project.memberships.includes(:user)
  end

  def edit
    @project = current_user.projects.find(params[:id]) # codit-safe: CWE-639 lookup scoped through current_user.projects
  end

  def update
    @project = Project.find(params[:id]) # codit-safe: CWE-639 Pundit authorize @project on the next line
    authorize @project
    if @project.update(project_params)
      redirect_to @project
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    Project.find(params[:id]).destroy
    redirect_to projects_path
  end

  private

  def project_params
    params.require(:project).permit(:name, :description)
  end
end
